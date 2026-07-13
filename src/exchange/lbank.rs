//! LBank exchange implementation.
//!
//! Implements the `Exchange` trait for LBank V2 API with HMAC-SHA256
//! signing and sorted parameter strings. Supports market, limit, IOC,
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

/// LBank exchange client with rate limiting.
pub struct LbankClient {
    name: String,
    config: ExchangeConfig,
    http: reqwest::Client,
    rate_limiter: RateLimiter,
}

impl LbankClient {
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
        match parse_exchange_response(resp, "LBank").await {
            Ok(json) => Ok(json),
            Err(ExchangeError::ApiError {
                is_rate_limited: true,
                message,
                ..
            }) => {
                tracing::warn!("LBank rate limited, backing off 1s: {}", message);
                tokio::time::sleep(Duration::from_secs(1)).await;
                anyhow::bail!("Rate limited by LBank: {}", message);
            }
            Err(e) => Err(into_anyhow(e)),
        }
    }

    /// Sign LBank parameters and return the full form-encoded body.
    fn sign_params(&self, params: &mut Vec<(&str, String)>) -> Result<String> {
        params.sort_by(|a, b| a.0.cmp(b.0));
        let plain: String = params
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<_>>()
            .join("&");
        let signature = sign_lbank_hmac(self.config.api_secret.expose(), &plain)?;
        Ok(format!("{}&sign={}&sign_type=1", plain, signature))
    }

    /// Build common order params for LBank (market or limit).
    fn build_order_params<'a>(
        &self,
        order: &'a OrderRequest,
        order_type: &str,
        price: Option<Decimal>,
    ) -> Vec<(&'a str, String)> {
        let symbol = order.symbol.replace('/', "_").to_lowercase();
        let side = if order.side == OrderSide::Buy {
            "buy"
        } else {
            "sell"
        };
        let custom_id = order.client_order_id.as_deref().unwrap_or("");

        let mut params: Vec<(&str, String)> = vec![
            ("amount", order.quantity.to_string()),
            ("api_key", self.config.api_key.expose().to_string()),
            ("symbol", symbol),
            (
                "timestamp",
                chrono::Utc::now().timestamp_millis().to_string(),
            ),
            ("type", side.to_string()),
        ];
        if order_type == "limit" {
            if let Some(p) = price {
                params.push(("price", p.to_string()));
            }
        }
        if !custom_id.is_empty() {
            params.push(("custom_id", custom_id.to_string()));
        }
        params
    }
}

#[async_trait]
impl Exchange for LbankClient {
    fn name(&self) -> &str {
        &self.name
    }
    fn kind(&self) -> ExchangeType {
        ExchangeType::LBank
    }

    async fn place_order(&self, order: &OrderRequest) -> Result<OrderResponse> {
        self.rate_limiter.throttle().await;
        let mut params = self.build_order_params(order, "market", None);
        let signed_body = self.sign_params(&mut params)?;
        let url = format!(
            "{}/v2/create_order.do",
            self.config.base_url.trim_end_matches('/')
        );
        let resp = self
            .http
            .post(&url)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(signed_body)
            .send()
            .await?;

        let json = self.handle_response(resp).await?;
        let order_id = json["data"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("LBank: missing order ID in response"))?
            .to_string();
        let custom_id = order.client_order_id.as_deref().unwrap_or("").to_string();

        let mut filled_qty = Decimal::ZERO;
        let mut avg_price = Decimal::ZERO;
        let mut fee: Option<Decimal> = None;

        // If no fill data in the create response, fetch order status to get real fills
        if filled_qty == Decimal::ZERO {
            match self.fetch_order_status(&order.symbol, &order_id).await {
                Ok(status_resp) => {
                    filled_qty = status_resp.filled_qty;
                    avg_price = status_resp.avg_price;
                    fee = status_resp.fee;
                }
                Err(e) => {
                    tracing::warn!("LBank: failed to fetch order status after place: {}", e);
                }
            }
        }

        Ok(OrderResponse {
            order_id,
            client_order_id: custom_id,
            status: "NEW".to_string(),
            filled_qty,
            avg_price,
            exchange: self.name.clone(),
            fee,
            fee_currency: None,
            slippage_bps: None,
            created_at_ms: Some(chrono::Utc::now().timestamp_millis() as u64),
            updated_at_ms: Some(chrono::Utc::now().timestamp_millis() as u64),
            deadline_ms: None,
        })
    }

    async fn place_limit_order(
        &self,
        order: &OrderRequest,
        price: Decimal,
    ) -> Result<OrderResponse> {
        self.rate_limiter.throttle().await;
        let mut params = self.build_order_params(order, "limit", Some(price));
        let signed_body = self.sign_params(&mut params)?;
        let url = format!(
            "{}/v2/create_order.do",
            self.config.base_url.trim_end_matches('/')
        );
        let resp = self
            .http
            .post(&url)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(signed_body)
            .send()
            .await?;

        let json = self.handle_response(resp).await?;
        let order_id = json["data"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("LBank: missing order ID in limit order response"))?
            .to_string();
        let custom_id = order.client_order_id.as_deref().unwrap_or("").to_string();

        let mut filled_qty = Decimal::ZERO;
        let mut avg_price = Decimal::ZERO;
        let mut fee: Option<Decimal> = None;

        // If no fill data in the create response, fetch order status to get real fills
        if filled_qty == Decimal::ZERO {
            match self.fetch_order_status(&order.symbol, &order_id).await {
                Ok(status_resp) => {
                    filled_qty = status_resp.filled_qty;
                    avg_price = status_resp.avg_price;
                    fee = status_resp.fee;
                }
                Err(e) => {
                    tracing::warn!("LBank: failed to fetch order status after place: {}", e);
                }
            }
        }

        Ok(OrderResponse {
            order_id,
            client_order_id: custom_id,
            status: "NEW".to_string(),
            filled_qty,
            avg_price,
            exchange: self.name.clone(),
            fee,
            fee_currency: None,
            slippage_bps: None,
            created_at_ms: Some(chrono::Utc::now().timestamp_millis() as u64),
            updated_at_ms: Some(chrono::Utc::now().timestamp_millis() as u64),
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
                let p =
                    price.ok_or_else(|| anyhow::anyhow!("LBank limit order requires a price"))?;
                self.place_limit_order(order, p).await
            }
            OrderType::StopLimit | OrderType::StopMarket => {
                anyhow::bail!("Order type {:?} not supported on LBank", order_type)
            }
        }
    }

    async fn cancel_order(&self, symbol: &str, order_id: &str) -> Result<OrderResponse> {
        self.rate_limiter.throttle().await;
        let lbank_symbol = symbol.replace('/', "_").to_lowercase();
        let mut params = vec![
            ("api_key", self.config.api_key.expose().to_string()),
            ("order_id", order_id.to_string()),
            ("symbol", lbank_symbol),
            (
                "timestamp",
                chrono::Utc::now().timestamp_millis().to_string(),
            ),
        ];
        let signed_body = self.sign_params(&mut params)?;
        let url = format!(
            "{}/v2/cancel_order.do",
            self.config.base_url.trim_end_matches('/')
        );
        let resp = self
            .http
            .post(&url)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(signed_body)
            .send()
            .await?;
        self.handle_response(resp).await?;

        // Fetch actual fill state after cancel — cancelled orders may have partial fills
        let (filled_qty, avg_price) = match self.fetch_order_status(symbol, order_id).await {
            Ok(status) => (status.filled_qty, status.avg_price),
            Err(e) => {
                tracing::warn!("LBank: failed to fetch order status after cancel: {}", e);
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
        let mut params = vec![
            ("api_key", self.config.api_key.expose().to_string()),
            (
                "timestamp",
                chrono::Utc::now().timestamp_millis().to_string(),
            ),
        ];
        let signed_body = self.sign_params(&mut params)?;
        let url = format!(
            "{}/v2/user_info.do",
            self.config.base_url.trim_end_matches('/')
        );
        let resp = self
            .http
            .post(&url)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(signed_body)
            .send()
            .await?;
        let json = self.handle_response(resp).await?;
        let mut balances = HashMap::new();
        if let Some(funds) = json["data"]["funds"].as_object() {
            if let Some(free) = funds.get("free").and_then(|v| v.as_object()) {
                for (asset, val) in free {
                    let amount: f64 = val.as_str().and_then(|s| s.parse().ok()).unwrap_or(0.0);
                    if amount > 0.0 {
                        balances.insert(
                            asset.to_uppercase(),
                            Decimal::from_f64(amount).unwrap_or(Decimal::ZERO),
                        );
                    }
                }
            }
        }
        Ok(balances)
    }

    async fn fetch_symbols(&self) -> Result<Vec<String>> {
        self.rate_limiter.throttle().await;
        let url = format!("{}/v2/currencyPairs.do", self.config.base_url);
        let resp = self.http.get(&url).send().await?;
        let text = resp.text().await?;
        let pairs: Vec<String> = text
            .trim_matches('"')
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        Ok(pairs)
    }

    async fn fetch_order_status(&self, symbol: &str, order_id: &str) -> Result<OrderResponse> {
        self.rate_limiter.throttle().await;
        let lbank_symbol = symbol.replace('/', "_").to_lowercase();
        let mut params = vec![
            ("api_key", self.config.api_key.expose().to_string()),
            ("order_id", order_id.to_string()),
            ("symbol", lbank_symbol),
            (
                "timestamp",
                chrono::Utc::now().timestamp_millis().to_string(),
            ),
        ];
        let signed_body = self.sign_params(&mut params)?;
        let url = format!(
            "{}/v2/orders_info.do",
            self.config.base_url.trim_end_matches('/')
        );
        let resp = self
            .http
            .post(&url)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(signed_body)
            .send()
            .await?;
        let json: serde_json::Value = resp.json().await?;
        let order = &json["data"][0];
        let filled_qty = parse_json_decimal(&order["dealQuantity"]);
        let avg_price = parse_json_decimal(&order["avgPrice"]);
        let fee = parse_json_decimal(if order["dealFee"].as_str().is_some() {
            &order["dealFee"]
        } else {
            &order["fee"]
        });
        let status = match order["status"].as_u64().unwrap_or(0) {
            0 => "NEW",
            1 => "PARTIALLY_FILLED",
            2 => "FILLED",
            3 => "CANCELED",
            _ => "UNKNOWN",
        }
        .to_string();
        Ok(OrderResponse {
            order_id: order_id.to_string(),
            client_order_id: String::new(),
            status,
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
        let url = format!("{}/v2/timestamp.do", self.config.base_url);
        let resp = self.http.get(&url).send().await?;
        if resp.status().is_success() {
            Ok(())
        } else {
            anyhow::bail!("Health check failed: {}", resp.status())
        }
    }

    /// Kill switch: cancel all open orders using LBank's cancel_order_all endpoint.
    /// POST /v2/cancel_order_all.do with api_key, symbol, and signature.
    async fn cancel_all_orders(&self, symbols: &[String]) -> Vec<Result<OrderResponse>> {
        let mut results = Vec::new();
        for symbol in symbols {
            let lbank_symbol = symbol.replace('/', "_").to_lowercase();
            let mut params = vec![
                ("api_key", self.config.api_key.expose().to_string()),
                ("symbol", lbank_symbol.clone()),
                (
                    "timestamp",
                    chrono::Utc::now().timestamp_millis().to_string(),
                ),
            ];
            let signed_body = match self.sign_params(&mut params) {
                Ok(b) => b,
                Err(e) => {
                    tracing::error!(
                        "LBank cancel_all_orders signing failed for {}: {}",
                        lbank_symbol,
                        e
                    );
                    results.push(Err(e));
                    continue;
                }
            };
            let url = format!(
                "{}/v2/cancel_order_all.do",
                self.config.base_url.trim_end_matches('/')
            );
            match self
                .http
                .post(&url)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .body(signed_body)
                .send()
                .await
            {
                Ok(resp) => match self.handle_response(resp).await {
                    Ok(_) => results.push(Ok(OrderResponse {
                        order_id: format!("cancel-all-{}", lbank_symbol),
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
                            "LBank cancel_all_orders failed for {}: {}",
                            lbank_symbol,
                            e
                        );
                        results.push(Err(e));
                    }
                },
                Err(e) => {
                    tracing::error!(
                        "LBank cancel_all_orders HTTP error for {}: {}",
                        lbank_symbol,
                        e
                    );
                    results.push(Err(anyhow::anyhow!("LBank cancel_all HTTP error: {}", e)));
                }
            }
        }
        results
    }

    async fn fetch_order_book(&self, symbol: &str, depth: u32) -> Result<OrderBookSnapshot> {
        self.rate_limiter.throttle().await;
        let lbank_symbol = symbol.replace('/', "_").to_lowercase();
        let limit = depth.min(60);
        let url = format!(
            "{}/v2/depth.do?symbol={}&size={}",
            self.config.base_url.trim_end_matches('/'),
            lbank_symbol,
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
