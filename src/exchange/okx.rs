//! OKX exchange implementation.
//!
//! Implements the `Exchange` trait for OKX V5 API with HMAC-SHA256
//! signing using base64-decoded secret. Supports market, limit, IOC,
//! and FOK order types with rate limit detection and backoff.

use async_trait::async_trait;
use rust_decimal::Decimal;
use std::collections::HashMap;

use crate::exchange::config::ExchangeConfig;
use crate::exchange::common::*;
use crate::exchange::exchange_trait::*;
use crate::exchange::types::*;
use anyhow::Result;

/// OKX exchange client with rate limiting.
pub struct OkxClient {
    name: String,
    config: ExchangeConfig,
    http: reqwest::Client,
    rate_limiter: RateLimiter,
}

impl OkxClient {
    pub fn new(name: String, config: ExchangeConfig) -> Result<Self> {
        // OKX requires a passphrase for all authenticated V5 API requests.
        // In live mode, a missing passphrase causes every authenticated request
        // to fail with hard-to-diagnose auth errors.
        //
        // We log a warning rather than bailing because:
        // 1. Paper mode doesn't need a passphrase (no authenticated calls)
        // 2. The ExchangeClient::new() constructor doesn't know the trading mode
        // 3. Bailing here breaks paper-mode tests and instance creation
        //
        // The caller (main.rs) should validate that the passphrase is set when
        // mode == Live before starting the engine.
        let passphrase = config.passphrase_str();
        if passphrase.is_empty() {
            tracing::warn!(
                "OKX client '{}' created without passphrase — authenticated requests will fail. \
                 Set OKX_PASSPHRASE for live trading.",
                name
            );
        }
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

    /// Common OKX order-signing and sending logic.
    async fn send_okx_order(&self, body: serde_json::Value) -> Result<serde_json::Value> {
        // TODO: Add monotonic counter to prevent nonce collisions within the
        // same millisecond on rapid successive requests.
        let timestamp = chrono::Utc::now()
            .format("%Y-%m-%dT%H:%M:%S%.3fZ")
            .to_string();
        let body_str = serde_json::to_string(&body)?;
        let sign_str = format!("{}POST/api/v5/trade/order{}", timestamp, body_str);
        let signature =
            sign_hmac_base64_with_decoded_key(self.config.api_secret.expose(), &sign_str)?;
        let url = format!("{}/api/v5/trade/order", self.config.base_url);
        let resp = self
            .http
            .post(&url)
            .header("OK-ACCESS-KEY", self.config.api_key.expose())
            .header("OK-ACCESS-SIGN", &signature)
            .header("OK-ACCESS-TIMESTAMP", &timestamp)
            .header(
                "OK-ACCESS-PASSPHRASE",
                self.config.passphrase_str(),
            )
            .header("Content-Type", "application/json")
            .body(body_str)
            .send()
            .await?;

        self.handle_response(resp).await
    }

    /// Parse the OKX order response into an OrderResponse, fetching fill
    /// data from fetch_order_status when the create response has none.
    /// Normalize OKX order state to uppercase standard form.
    fn normalize_okx_state(state: &str) -> String {
        match state.to_lowercase().as_str() {
            "live" => "LIVE".to_string(),
            "partially_filled" => "PARTIALLY_FILLED".to_string(),
            "filled" => "FILLED".to_string(),
            "canceled" | "cancelled" => "CANCELED".to_string(),
            _ => state.to_uppercase(), // Unknown states: uppercase for consistency
        }
    }

    async fn parse_okx_order_response(
        &self,
        json: &serde_json::Value,
        symbol: &str,
    ) -> Result<OrderResponse> {
        let data = &json["data"][0];
        let order_id = data["ordId"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("OKX: missing ordId in order response"))?
            .to_string();
        let client_order_id = data["clOrdId"].as_str().unwrap_or("").to_string();

        let mut filled_qty = Decimal::ZERO;
        let mut avg_price = Decimal::ZERO;
        let mut status = "NEW".to_string();
        let mut fee = Decimal::ZERO;

        let fill_sz = parse_json_decimal(&data["fillSz"]);
        if fill_sz > Decimal::ZERO {
            filled_qty = fill_sz;
            avg_price = parse_json_decimal(&data["avgPx"]);
            status = Self::normalize_okx_state(data["state"].as_str().unwrap_or("unknown"));
            fee = parse_json_decimal(&data["fee"]);
        }

        if filled_qty == Decimal::ZERO {
            match self.fetch_order_status(symbol, &order_id).await {
                Ok(status_resp) => {
                    filled_qty = status_resp.filled_qty;
                    avg_price = status_resp.avg_price;
                    status = status_resp.status;
                    fee = status_resp.fee.unwrap_or(Decimal::ZERO);
                }
                Err(e) => {
                    tracing::warn!("OKX: failed to fetch order status after place: {}", e);
                }
            }
        }

        let final_fee = if fee > Decimal::ZERO {
            fee
        } else {
            data["fee"]
                .as_str()
                .map(|s| s.parse::<Decimal>().unwrap_or(Decimal::ZERO))
                .unwrap_or(Decimal::ZERO)
        };
        let fee_currency = data["feeCcy"].as_str().map(String::from);

        let now_ms = chrono::Utc::now().timestamp_millis() as u64;
        Ok(OrderResponse {
            order_id,
            client_order_id,
            status,
            filled_qty,
            avg_price,
            exchange: self.name.clone(),
            fee: Some(final_fee),
            fee_currency,
            slippage_bps: Some(Decimal::ZERO),
            created_at_ms: Some(now_ms),
            updated_at_ms: Some(now_ms),
            deadline_ms: None,
        })
    }
}

#[async_trait]
impl Exchange for OkxClient {
    fn name(&self) -> &str {
        &self.name
    }
    fn kind(&self) -> ExchangeType {
        ExchangeType::Okx
    }

    async fn place_order(&self, order: &OrderRequest) -> Result<OrderResponse> {
        self.rate_limiter.throttle().await;
        let side = if order.side == OrderSide::Buy {
            "buy"
        } else {
            "sell"
        };
        let inst_id = order.symbol.replace('/', "-");

        let mut body = serde_json::json!({
            "instId": inst_id,
            "tdMode": "cash",
            "side": side,
            "ordType": "market",
            "sz": order.quantity.to_string(),
        });
        if let Some(ref client_oid) = order.client_order_id {
            if !client_oid.is_empty() {
                body["clOrdId"] = serde_json::Value::String(client_oid.clone());
            }
        }

        let json = self.send_okx_order(body).await?;
        self.parse_okx_order_response(&json, &order.symbol).await
    }

    async fn cancel_order(&self, symbol: &str, order_id: &str) -> Result<OrderResponse> {
        self.rate_limiter.throttle().await;
        let timestamp = chrono::Utc::now()
            .format("%Y-%m-%dT%H:%M:%S%.3fZ")
            .to_string();
        let body = serde_json::json!({ "instId": symbol.replace('/', "-"), "ordId": order_id });
        let body_str = serde_json::to_string(&body)?;
        let sign_str = format!("{}POST/api/v5/trade/cancel-order{}", timestamp, body_str);
        let signature =
            sign_hmac_base64_with_decoded_key(self.config.api_secret.expose(), &sign_str)?;
        let url = format!("{}/api/v5/trade/cancel-order", self.config.base_url);
        let resp = self
            .http
            .post(&url)
            .header("OK-ACCESS-KEY", self.config.api_key.expose())
            .header("OK-ACCESS-SIGN", &signature)
            .header("OK-ACCESS-TIMESTAMP", &timestamp)
            .header(
                "OK-ACCESS-PASSPHRASE",
                self.config.passphrase_str(),
            )
            .header("Content-Type", "application/json")
            .body(body_str)
            .send()
            .await?;

        let json = self.handle_response(resp).await?;
        let _data = &json["data"][0];

        let (filled_qty, avg_price) = match self.fetch_order_status(symbol, order_id).await {
            Ok(status) => (status.filled_qty, status.avg_price),
            Err(e) => {
                tracing::warn!(
                    "{}: failed to fetch order status after cancel: {}",
                    self.name(),
                    e
                );
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
        let timestamp = chrono::Utc::now()
            .format("%Y-%m-%dT%H:%M:%S%.3fZ")
            .to_string();
        let sign_str = format!("{}GET/api/v5/account/balance", timestamp);
        let signature =
            sign_hmac_base64_with_decoded_key(self.config.api_secret.expose(), &sign_str)?;
        let url = format!("{}/api/v5/account/balance", self.config.base_url);
        let resp = self
            .http
            .get(&url)
            .header("OK-ACCESS-KEY", self.config.api_key.expose())
            .header("OK-ACCESS-SIGN", &signature)
            .header("OK-ACCESS-TIMESTAMP", &timestamp)
            .header(
                "OK-ACCESS-PASSPHRASE",
                self.config.passphrase_str(),
            )
            .send()
            .await?;

        let json = self.handle_response(resp).await?;

        let mut balances = HashMap::new();
        if let Some(data) = json["data"].as_array() {
            for account in data {
                if let Some(details) = account["details"].as_array() {
                    for detail in details {
                        let avail: f64 = parse_json_f64(&detail["availBal"]);
                        if avail > 0.0 {
                            let ccy = match extract_currency(&detail["ccy"], "ccy", "OKX") {
                            Some(c) => c,
                            None => continue,
                        };
                            let d = balance_f64_to_decimal(avail, "okx", &ccy);
                            if d > Decimal::ZERO {
                                balances.insert(ccy.to_string(), d);
                            }
                        }
                    }
                }
            }
        }
        Ok(balances)
    }

    async fn fetch_symbols(&self) -> Result<Vec<String>> {
        let url = format!(
            "{}/api/v5/public/instruments?instType=SPOT&limit=500",
            self.config.base_url
        );
        let resp = self.http.get(&url).send().await?;
        let json: serde_json::Value = resp.json().await?;
        let symbols = json["data"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter(|s| s["state"].as_str() == Some("live"))
                    .filter_map(|s| s["instId"].as_str().map(|s| s.replace('-', "/")))
                    .collect()
            })
            .unwrap_or_default();
        Ok(symbols)
    }

    async fn fetch_order_status(&self, symbol: &str, order_id: &str) -> Result<OrderResponse> {
        self.rate_limiter.throttle().await;
        let timestamp = chrono::Utc::now()
            .format("%Y-%m-%dT%H:%M:%S%.3fZ")
            .to_string();
        let query = format!("instId={}&ordId={}", symbol.replace('/', "-"), order_id);
        let sign_str = format!("{}GET/api/v5/trade/order?{}", timestamp, query);
        let signature =
            sign_hmac_base64_with_decoded_key(self.config.api_secret.expose(), &sign_str)?;
        let url = format!("{}/api/v5/trade/order?{}", self.config.base_url, query);
        let resp = self
            .http
            .get(&url)
            .header("OK-ACCESS-KEY", self.config.api_key.expose())
            .header("OK-ACCESS-SIGN", &signature)
            .header("OK-ACCESS-TIMESTAMP", &timestamp)
            .header(
                "OK-ACCESS-PASSPHRASE",
                self.config.passphrase_str(),
            )
            .send()
            .await?;

        let json = self.handle_response(resp).await?;

        let data = &json["data"][0];
        let fee = parse_json_decimal(&data["fee"]);
        let fee_currency = data["feeCcy"].as_str().map(String::from);
        Ok(OrderResponse {
            order_id: order_id.to_string(),
            client_order_id: extract_client_order_id(&data["clOrdId"], "clOrdId", "OKX"),
            status: Self::normalize_okx_state(data["state"].as_str().unwrap_or("unknown")),
            filled_qty: parse_json_decimal(&data["fillSz"]),
            avg_price: parse_json_decimal(&data["avgPx"]),
            exchange: self.name.clone(),
            fee: Some(fee),
            fee_currency,
            slippage_bps: None,
            created_at_ms: None,
            updated_at_ms: None,
            deadline_ms: None,
        })
    }

    async fn cancel_all_orders(&self, symbols: &[String]) -> Vec<Result<OrderResponse>> {
        let mut results = Vec::new();
        for symbol in symbols {
            let inst_id = symbol.replace('/', "-");
            let timestamp = chrono::Utc::now()
                .format("%Y-%m-%dT%H:%M:%S%.3fZ")
                .to_string();
            let body = serde_json::json!({ "instId": inst_id });
            let body_str = match serde_json::to_string(&body) {
                Ok(s) => s,
                Err(e) => {
                    results.push(Err(anyhow::anyhow!(
                        "OKX cancel_all serialize error: {}",
                        e
                    )));
                    continue;
                }
            };
            let sign_str = format!("{}POST/api/v5/trade/cancel-all{}", timestamp, body_str);
            let signature =
                match sign_hmac_base64_with_decoded_key(self.config.api_secret.expose(), &sign_str)
            {
                Ok(s) => s,
                Err(e) => {
                    results.push(Err(e));
                    continue;
                }
            };
            let url = format!("{}/api/v5/trade/cancel-all", self.config.base_url);
            match self
                .http
                .post(&url)
                .header("OK-ACCESS-KEY", self.config.api_key.expose())
                .header("OK-ACCESS-SIGN", &signature)
                .header("OK-ACCESS-TIMESTAMP", &timestamp)
                .header(
                    "OK-ACCESS-PASSPHRASE",
                    self.config.passphrase_str(),
                )
                .header("Content-Type", "application/json")
                .body(body_str)
                .send()
                .await
            {
                Ok(resp) => match self.handle_response(resp).await {
                    Ok(_) => results.push(Ok(OrderResponse {
                        order_id: format!("cancel-all-{}", inst_id),
                        client_order_id: String::new(),
                        status: "CANCELED".to_string(),
                        filled_qty: Decimal::ZERO,
                        avg_price: Decimal::ZERO,
                        exchange: self.name.clone(),
                        fee: None,
                        fee_currency: None,
                        slippage_bps: None,
                        created_at_ms: None,
                        updated_at_ms: None,
                        deadline_ms: None,
                    })),
                    Err(e) => results.push(Err(e)),
                },
                Err(e) => {
                    results.push(Err(anyhow::anyhow!("OKX cancel_all HTTP error: {}", e)));
                }
            }
        }
        results
    }

    async fn health_check(&self) -> Result<()> {
        let url = format!("{}/api/v5/public/time", self.config.base_url);
        let resp = self.http.get(&url).send().await?;
        if resp.status().is_success() {
            Ok(())
        } else {
            anyhow::bail!("Health check failed: {}", resp.status())
        }
    }

    async fn place_limit_order(
        &self,
        order: &OrderRequest,
        price: Decimal,
    ) -> Result<OrderResponse> {
        self.rate_limiter.throttle().await;
        let side = if order.side == OrderSide::Buy {
            "buy"
        } else {
            "sell"
        };
        let inst_id = order.symbol.replace('/', "-");

        let mut body = serde_json::json!({
            "instId": inst_id,
            "tdMode": "cash",
            "side": side,
            "ordType": "limit",
            "sz": order.quantity.to_string(),
            "px": price.to_string(),
        });
        if let Some(ref client_oid) = order.client_order_id {
            if !client_oid.is_empty() {
                body["clOrdId"] = serde_json::Value::String(client_oid.clone());
            }
        }

        let json = self.send_okx_order(body).await?;
        self.parse_okx_order_response(&json, &order.symbol).await
    }

    async fn place_order_with_type(
        &self,
        order: &OrderRequest,
        order_type: OrderType,
        price: Option<Decimal>,
    ) -> Result<OrderResponse> {
        self.rate_limiter.throttle().await;
        let side = if order.side == OrderSide::Buy {
            "buy"
        } else {
            "sell"
        };
        let inst_id = order.symbol.replace('/', "-");

        let okx_ord_type = match order_type {
            OrderType::Market => "market",
            OrderType::Limit => match order.time_in_force {
                TimeInForce::IOC => "ioc",
                TimeInForce::FOK => "fok",
                _ => "limit",
            },
            _ => anyhow::bail!(
                "Order type {:?} not supported on {}",
                order_type,
                self.name()
            ),
        };

        let mut body = serde_json::json!({
            "instId": inst_id,
            "tdMode": "cash",
            "side": side,
            "ordType": okx_ord_type,
            "sz": order.quantity.to_string(),
        });

        if order_type != OrderType::Market {
            let p = price.ok_or_else(|| {
                anyhow::anyhow!("{} order requires a price on {}", okx_ord_type, self.name())
            })?;
            body["px"] = serde_json::Value::String(p.to_string());
        }

        if let Some(ref client_oid) = order.client_order_id {
            if !client_oid.is_empty() {
                body["clOrdId"] = serde_json::Value::String(client_oid.clone());
            }
        }

        let json = self.send_okx_order(body).await?;
        self.parse_okx_order_response(&json, &order.symbol).await
    }

    async fn fetch_order_book(&self, symbol: &str, depth: u32) -> Result<OrderBookSnapshot> {
        let inst_id = symbol.replace('/', "-");
        let sz = match depth {
            0..=1 => 1,
            2..=5 => 5,
            6..=10 => 10,
            11..=20 => 20,
            21..=50 => 50,
            51..=100 => 100,
            101..=200 => 200,
            _ => 400,
        };
        let url = format!(
            "{}/api/v5/market/books?instId={}&sz={}",
            self.config.base_url, inst_id, sz
        );
        let resp = self.http.get(&url).send().await?;
        let json: serde_json::Value = resp.json().await?;

        let data = &json["data"][0];

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

        let timestamp_ms = data["ts"]
            .as_str()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or_else(|| chrono::Utc::now().timestamp_millis() as u64);

        Ok(OrderBookSnapshot {
            symbol: symbol.to_string(),
            exchange: self.name.clone(),
            bids,
            asks,
            timestamp_us: timestamp_ms * 1000,
        })
    }
}