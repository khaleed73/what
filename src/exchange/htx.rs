//! HTX (Huobi Global) exchange implementation.
//!
//! Implements the `Exchange` trait for HTX with HMAC-SHA256 signing
//! and signed URL construction. Supports market, limit, IOC, and FOK
//! order types with rate limit detection and backoff.

use async_trait::async_trait;
use rust_decimal::prelude::FromPrimitive;
use rust_decimal::Decimal;
use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::time::Duration;

use crate::exchange::config::ExchangeConfig;
use crate::exchange::common::*;
use crate::exchange::exchange_trait::*;
use crate::exchange::types::*;
use anyhow::Result;

/// HTX exchange client with rate limiting and dynamic account-id caching.
pub struct HtxClient {
    name: String,
    config: ExchangeConfig,
    http: reqwest::Client,
    rate_limiter: RateLimiter,
    /// Cached account-id fetched from HTX on first authenticated call.
    account_id: std::sync::atomic::AtomicU64,
}

impl HtxClient {
    pub fn new(name: String, config: ExchangeConfig) -> Result<Self> {
        let timeout_secs = config.http_timeout_secs.unwrap_or(30);
        let http = build_http_client(timeout_secs)?;
        Ok(Self {
            name,
            config,
            http,
            rate_limiter: RateLimiter::new(100),
            account_id: std::sync::atomic::AtomicU64::new(0),
        })
    }

    /// Ensure we have a valid HTX account-id cached.
    /// HTX requires the user's account-id (obtained from /v1/account/accounts)
    /// in every order request. We fetch and cache it on the first call.
    async fn ensure_account_id(&self) -> Result<u64> {
        let cached = self.account_id.load(std::sync::atomic::Ordering::Relaxed);
        if cached != 0 {
            return Ok(cached);
        }
        let timestamp = chrono::Utc::now().timestamp_millis().to_string();
        let _sign_str = format!("GET\napi.huobi.pro\n/v1/account/accounts\n");
        let signature = sign_htx(
            self.config.api_secret.expose(),
            "GET",
            "api.huobi.pro",
            "/v1/account/accounts",
            "",
        )?;
        let url = format!("{}/v1/account/accounts", self.config.base_url);
        let resp = self
            .http
            .get(&url)
            .header("X-HB-APIKEY", self.config.api_key.expose())
            .header("X-HB-SIGNATURE", &signature)
            .header("X-HB-TIMESTAMP", &timestamp)
            .send()
            .await?;
        let json: serde_json::Value = resp.json().await?;
        let aid = json["data"][0]["id"]
            .as_u64()
            .ok_or_else(|| anyhow::anyhow!("HTX: failed to parse account-id"))?;
        self.account_id.store(aid, std::sync::atomic::Ordering::Relaxed);
        Ok(aid)
    }

    /// Handle exchange response with rate limit detection and backoff.
    async fn handle_response(&self, resp: reqwest::Response) -> Result<serde_json::Value> {
        match parse_exchange_response(resp, "HTX").await {
            Ok(json) => Ok(json),
            Err(ExchangeError::ApiError {
                is_rate_limited: true,
                message,
                ..
            }) => {
                tracing::warn!("HTX rate limited, backing off 1s: {}", message);
                tokio::time::sleep(Duration::from_secs(1)).await;
                anyhow::bail!("Rate limited by HTX: {}", message);
            }
            Err(e) => Err(into_anyhow(e)),
        }
    }

    /// Build a signed URL with HMAC-SHA256 signature for HTX API requests.
    fn htx_signed_url(&self, path: &str, extra_params: &[(&str, String)]) -> Result<String> {
        let ts = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S").to_string();
        let mut params = vec![
            ("AccessKeyId", self.config.api_key.expose().to_string()),
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
        // B4 FIX: HTX requires signing METHOD\nhost\npath\nquery
        let base = self.config.base_url.trim_end_matches('/');
        let host = base
            .trim_start_matches("https://")
            .trim_start_matches("http://");
        let sign = sign_htx(self.config.api_secret.expose(), "GET", host, path, &query)?;
        Ok(format!("{}{}?{}&Signature={}", base, path, query, sign))
    }

    /// Build an HTX order body with type, price, and idempotency key.
    async fn build_order_body(
        &self,
        order: &OrderRequest,
        order_type_str: &str,
        price: Option<Decimal>,
    ) -> Result<serde_json::Value> {
        self.ensure_account_id().await?;
        let symbol = order.symbol.replace('/', "").to_lowercase();
        let mut body = serde_json::json!({
            "account-id": self.account_id.load(Ordering::Relaxed).to_string(),
            "amount": order.quantity.to_string(),
            "symbol": symbol,
            "type": order_type_str,
        });
        if let Some(p) = price {
            body["price"] = serde_json::Value::String(p.to_string());
        }
        if let Some(ref client_oid) = order.client_order_id {
            if !client_oid.is_empty() {
                body["client-order-id"] = serde_json::Value::String(client_oid.clone());
            }
        }
        Ok(body)
    }

    /// Send a signed POST order request to HTX.
    async fn send_htx_order(&self, body: serde_json::Value) -> Result<OrderResponse> {
        self.rate_limiter.throttle().await;
        let body_str = serde_json::to_string(&body)?;
        let url = self.htx_signed_url("/v1/order/orders/place", &[])?;
        let resp = self
            .http
            .post(&url)
            .header("Content-Type", "application/json")
            .body(body_str)
            .send()
            .await?;

        let json = self.handle_response(resp).await?;
        let order_id = json["data"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("HTX: missing order ID in response"))?
            .to_string();
        let client_oid = body
            .get("client-order-id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        Ok(OrderResponse {
            order_id,
            client_order_id: client_oid,
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
impl Exchange for HtxClient {
    fn name(&self) -> &str {
        &self.name
    }
    fn kind(&self) -> ExchangeType {
        ExchangeType::Htx
    }

    async fn place_order(&self, order: &OrderRequest) -> Result<OrderResponse> {
        let side = if order.side == OrderSide::Buy {
            "buy"
        } else {
            "sell"
        };
        let body = self.build_order_body(order, &format!("{}-market", side), None).await?;
        let mut resp = self.send_htx_order(body).await?;
        if resp.filled_qty == Decimal::ZERO {
            match self.fetch_order_status(&order.symbol, &resp.order_id).await {
                Ok(status_resp) => {
                    resp.filled_qty = status_resp.filled_qty;
                    resp.avg_price = status_resp.avg_price;
                    resp.fee = status_resp.fee;
                }
                Err(e) => {
                    tracing::warn!("HTX: failed to fetch order status after place: {}", e);
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
        let side = if order.side == OrderSide::Buy {
            "buy"
        } else {
            "sell"
        };
        let order_type_str = match order.time_in_force {
            TimeInForce::IOC => format!("{}-ioc", side),
            TimeInForce::FOK => format!("{}-fok", side),
            TimeInForce::GTC | TimeInForce::Day => format!("{}-limit", side),
        };
        let body = self.build_order_body(order, &order_type_str, Some(price)).await?;
        let mut resp = self.send_htx_order(body).await?;
        if resp.filled_qty == Decimal::ZERO {
            match self.fetch_order_status(&order.symbol, &resp.order_id).await {
                Ok(status_resp) => {
                    resp.filled_qty = status_resp.filled_qty;
                    resp.avg_price = status_resp.avg_price;
                    resp.fee = status_resp.fee;
                }
                Err(e) => {
                    tracing::warn!("HTX: failed to fetch order status after place: {}", e);
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
                let p = price.ok_or_else(|| anyhow::anyhow!("HTX limit order requires a price"))?;
                self.place_limit_order(order, p).await
            }
            OrderType::StopLimit | OrderType::StopMarket => {
                anyhow::bail!("Order type {:?} not supported on HTX", order_type)
            }
        }
    }

    async fn cancel_order(&self, symbol: &str, order_id: &str) -> Result<OrderResponse> {
        self.rate_limiter.throttle().await;
        let url =
            self.htx_signed_url(&format!("/v1/order/orders/{}/submitcancel", order_id), &[])?;
        let resp = self.http.post(&url).send().await?;
        self.handle_response(resp).await?;

        // Fetch actual fill state after cancel — cancelled orders may have partial fills
        let (filled_qty, avg_price) = match self.fetch_order_status(symbol, order_id).await {
            Ok(status) => (status.filled_qty, status.avg_price),
            Err(e) => {
                tracing::warn!("HTX: failed to fetch order status after cancel: {}", e);
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
        let accts_url = self.htx_signed_url("/v1/account/accounts", &[])?;
        let resp = self.http.get(&accts_url).send().await?;
        let json = self.handle_response(resp).await?;
        let account_id = json["data"]
            .as_array()
            .and_then(|a| a.first())
            .and_then(|a| a["id"].as_i64())
            .unwrap_or(0);
        let bal_url =
            self.htx_signed_url(&format!("/v1/account/accounts/{}/balance", account_id), &[])?;
        let resp = self.http.get(&bal_url).send().await?;
        let json = self.handle_response(resp).await?;
        let mut balances = HashMap::new();
        if let Some(arr) = json["data"]["list"].as_array() {
            for b in arr {
                let free: f64 = b["balance"]
                    .as_str()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0.0);
                if free > 0.0 {
                    let currency = b["currency"].as_str().unwrap_or("").to_uppercase();
                    balances.insert(currency, Decimal::from_f64(free).unwrap_or(Decimal::ZERO));
                }
            }
        }
        Ok(balances)
    }

    async fn fetch_symbols(&self) -> Result<Vec<String>> {
        self.rate_limiter.throttle().await;
        let url = format!(
            "{}/v1/common/symbols",
            self.config.base_url.trim_end_matches('/')
        );
        let resp = self.http.get(&url).send().await?;
        let json: serde_json::Value = resp.json().await?;
        Ok(json["data"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter(|s| s["state"].as_str() == Some("online"))
                    .filter_map(|s| {
                        let base = s["base-currency"].as_str()?;
                        let quote = s["quote-currency"].as_str()?;
                        Some(format!("{}/{}", base.to_uppercase(), quote.to_uppercase()))
                    })
                    .collect()
            })
            .unwrap_or_default())
    }

    async fn fetch_order_status(&self, _symbol: &str, order_id: &str) -> Result<OrderResponse> {
        self.rate_limiter.throttle().await;
        let url = self.htx_signed_url(&format!("/v1/order/orders/{}", order_id), &[])?;
        let resp = self.http.get(&url).send().await?;
        let json: serde_json::Value = resp.json().await?;
        let o = &json["data"];
        let status = match o["state"].as_str().unwrap_or("") {
            "submitted" => "NEW",
            "partial-filled" => "PARTIALLY_FILLED",
            "filled" => "FILLED",
            "canceled" => "CANCELED",
            "partial-canceled" => "PARTIALLY_CANCELED",
            _ => "UNKNOWN",
        };
        let filled_qty = parse_json_decimal(&o["field-amount"]);
        let field_cash = parse_json_decimal(&o["field-cash-amount"]);
        let avg_price = if filled_qty > Decimal::ZERO {
            field_cash / filled_qty
        } else {
            Decimal::ZERO
        };
        let fee = parse_json_decimal(&o["field-fees"]);
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
        let url = format!("{}/v1/common/timestamp", self.config.base_url);
        let resp = self.http.get(&url).send().await?;
        if resp.status().is_success() {
            Ok(())
        } else {
            anyhow::bail!("Health check failed: {}", resp.status())
        }
    }

    /// Kill switch: cancel all open orders using HTX's batchCancelOpen endpoint.
    /// POST /v1/order/orders/batchCancelOpen with symbol param cancels all open orders for that symbol.
    async fn cancel_all_orders(&self, symbols: &[String]) -> Vec<Result<OrderResponse>> {
        let mut results = Vec::new();
        for symbol in symbols {
            let htx_symbol = symbol.replace('/', "").to_lowercase();
            let url = match self.htx_signed_url(
                "/v1/order/orders/batchCancelOpen",
                &[("symbol", htx_symbol.clone())],
            ) {
                Ok(u) => u,
                Err(e) => {
                    tracing::error!(
                        "HTX cancel_all_orders signed URL failed for {}: {}",
                        htx_symbol,
                        e
                    );
                    results.push(Err(e));
                    continue;
                }
            };
            match self.http.post(&url).send().await {
                Ok(resp) => match self.handle_response(resp).await {
                    Ok(_) => results.push(Ok(OrderResponse {
                        order_id: format!("cancel-all-{}", htx_symbol),
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
                        tracing::error!("HTX cancel_all_orders failed for {}: {}", htx_symbol, e);
                        results.push(Err(e));
                    }
                },
                Err(e) => {
                    tracing::error!("HTX cancel_all_orders HTTP error for {}: {}", htx_symbol, e);
                    results.push(Err(anyhow::anyhow!("HTX cancel_all HTTP error: {}", e)));
                }
            }
        }
        results
    }

    async fn fetch_order_book(&self, symbol: &str, depth: u32) -> Result<OrderBookSnapshot> {
        self.rate_limiter.throttle().await;
        let htx_symbol = symbol.replace('/', "").to_lowercase();
        let _type = match depth {
            0..=5 => "step0",
            6..=10 => "step1",
            11..=20 => "step2",
            21..=50 => "step3",
            51..=150 => "step4",
            _ => "step5",
        };
        let url = format!(
            "{}/market/depth?symbol={}&type={}",
            self.config.base_url.trim_end_matches('/'),
            htx_symbol,
            _type
        );
        let resp = self.http.get(&url).send().await?;
        let json: serde_json::Value = resp.json().await?;
        let tick = &json["tick"];

        let bids = tick["bids"]
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

        let asks = tick["asks"]
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

        let timestamp_ms = tick["ts"].as_u64().unwrap_or(0);

        Ok(OrderBookSnapshot {
            symbol: symbol.to_string(),
            exchange: self.name.clone(),
            bids,
            asks,
            timestamp_us: timestamp_ms * 1000,
        })
    }
}
