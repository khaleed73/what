//! Binance exchange implementation.
//!
//! Implements the `Exchange` trait for Binance, including HMAC-SHA256
//! request signing with server time synchronization.

use async_trait::async_trait;
use rust_decimal::prelude::FromPrimitive;
use rust_decimal::Decimal;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

use crate::exchange::config::ExchangeConfig;
use crate::exchange::common::*;
use crate::exchange::exchange_trait::*;
use crate::exchange::types::*;
use anyhow::{Context, Result};

/// Binance exchange client with server time synchronization.
pub struct BinanceClient {
    name: String,
    config: ExchangeConfig,
    http: reqwest::Client,
    rate_limiter: RateLimiter,
    time_offset_ms: Arc<RwLock<i64>>,
    time_sync_at: Arc<RwLock<Option<Instant>>>,
    seen_assets: Arc<RwLock<HashSet<String>>>,
}

    /// Default HTTP timeout in seconds when not configured.
    const DEFAULT_TIMEOUT_SECS: u64 = 30;
    /// Binance rate limit in requests per second.
    const BINANCE_RATE_LIMIT: u64 = 20;
    /// Time sync deadline in seconds.
    const TIME_SYNC_DEADLINE_SECS: u64 = 30;

impl BinanceClient {
    pub fn new(name: String, config: ExchangeConfig) -> Result<Self> {
        let timeout_secs = config.http_timeout_secs.unwrap_or(30);
        let http = build_http_client(timeout_secs)?;
        Ok(Self {
            name,
            config,
            http,
            rate_limiter: RateLimiter::new(BINANCE_RATE_LIMIT),
            time_offset_ms: Arc::new(RwLock::new(0)),
            time_sync_at: Arc::new(RwLock::new(None)),
            seen_assets: Arc::new(RwLock::new(HashSet::new())),
        })
    }

    /// Throttle before each signed/private API call.
    #[inline]
    async fn throttle(&self) {
        self.rate_limiter.throttle().await;
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

    /// Cancel all open orders for a single symbol via DELETE /api/v3/openOrders.
    async fn cancel_all_for_symbol(&self, binance_symbol: &str) -> Result<OrderResponse> {
        let timestamp = self.get_binance_timestamp().await?;
        let now_ms = chrono::Utc::now().timestamp_millis() as u64;
        let params = format!("symbol={}&timestamp={}", binance_symbol, timestamp);
        let signature = sign_hmac(self.config.api_secret.expose(), &params)?;
        self.throttle().await;
        let url = format!(
            "{}/api/v3/openOrders?{}&signature={}",
            self.config.base_url, params, signature
        );
        let resp = self
            .http
            .delete(&url)
            .header("X-MBX-APIKEY", self.config.api_key.expose())
            .send()
            .await?;
        // Binance returns 200 with empty body on success
        self.handle_response(resp).await?;
        Ok(OrderResponse {
            order_id: format!("cancel-all-{}", binance_symbol),
            client_order_id: String::new(),
            status: "CANCELED".to_string(),
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

    /// Get a server-synchronized timestamp, re-syncing every 30 seconds.
    async fn get_binance_timestamp(&self) -> Result<u64> {
        let sync_deadline = Duration::from_secs(TIME_SYNC_DEADLINE_SECS);
        let needs_sync = {
            let last = self.time_sync_at.read().await;
            last.map(|t| t.elapsed() > sync_deadline).unwrap_or(true)
        };
        if needs_sync {
            let url = format!("{}/api/v3/time", self.config.base_url);
            let resp = self.http.get(&url).send().await?;
            let json: serde_json::Value = resp.json().await?;
            let server_time = json["serverTime"].as_u64().context("Missing serverTime")?;
            let local_now = chrono::Utc::now().timestamp_millis() as u64;
            *self.time_offset_ms.write().await = server_time as i64 - local_now as i64;
            *self.time_sync_at.write().await = Some(Instant::now());
            Ok(server_time)
        } else {
            let offset = *self.time_offset_ms.read().await;
            let local_now = chrono::Utc::now().timestamp_millis();
            local_now.checked_add(offset)
                .and_then(|v| if v >= 0 { Some(v as u64) } else { None })
                .ok_or_else(|| anyhow::anyhow!("timestamp underflow: local={}, offset={}", local_now, offset))
        }
    }
}

#[async_trait]
impl Exchange for BinanceClient {
    fn name(&self) -> &str {
        &self.name
    }
    fn kind(&self) -> ExchangeType {
        ExchangeType::Binance
    }

    async fn place_order(&self, order: &OrderRequest) -> Result<OrderResponse> {
        let timestamp = self.get_binance_timestamp().await?;
        let now_ms = chrono::Utc::now().timestamp_millis() as u64;
        let side = if order.side == OrderSide::Buy {
            "BUY"
        } else {
            "SELL"
        };
        let symbol = order.symbol.replace('/', "");
        let mut params = format!(
            "symbol={}&side={}&type=MARKET&quantity={}&timestamp={}",
            symbol, side, order.quantity, timestamp
        );
        // Add newClientOrderId for idempotency
        if let Some(ref client_oid) = order.client_order_id {
            if !client_oid.is_empty() {
                params = format!("{}&newClientOrderId={}", params, client_oid);
            }
        }
        let signature = sign_hmac(self.config.api_secret.expose(), &params)?;
        self.throttle().await;
        let url = format!(
            "{}/api/v3/order?{}&signature={}",
            self.config.base_url, params, signature
        );
        let resp = self
            .http
            .post(&url)
            .header("X-MBX-APIKEY", self.config.api_key.expose())
            .header("Content-Type", "application/x-www-form-urlencoded")
            .send()
            .await?;

        let json = parse_exchange_response(resp, "Binance").await?;

        // Binance can return HTTP 200 with an error code in the body
        if let Some(code) = json["code"].as_i64() {
            if code != 0 {
                let msg = json["msg"].as_str().unwrap_or("unknown Binance error");
                anyhow::bail!("Binance API error (code {}): {}", code, msg);
            }
        }

        let executed_qty = parse_json_decimal(&json["executedQty"]);
        let cummulative_quote = parse_json_decimal(&json["cummulativeQuoteQty"]);
        let avg_price = if executed_qty > Decimal::ZERO {
            cummulative_quote / executed_qty
        } else {
            Decimal::ZERO
        };
        let fee: Decimal = json["fills"]
            .as_array()
            .map(|fills| {
                fills
                    .iter()
                    .filter_map(|f| {
                        f["commission"]
                            .as_str()
                            .map(|s| s.parse::<Decimal>().unwrap_or(dec!(0.001)))
                    })
                    .sum()
            })
            .unwrap_or(Decimal::ZERO);
        let fee_currency = json["fills"]
            .as_array()
            .and_then(|fills| fills.first())
            .and_then(|f| f["commissionAsset"].as_str())
            .map(String::from);
        Ok(OrderResponse {
            order_id: extract_order_id(&json["orderId"])?,
            client_order_id: extract_client_order_id(&json["clientOrderId"], "clientOrderId", "Binance"),
            status: json["status"].as_str().unwrap_or("UNKNOWN").to_string(),
            filled_qty: executed_qty,
            avg_price,
            exchange: self.name.clone(),
            fee: Some(fee),
            fee_currency,
            slippage_bps: None,
            created_at_ms: Some(now_ms),
            updated_at_ms: Some(now_ms),
            deadline_ms: None,
        })
    }

    async fn cancel_order(&self, symbol: &str, order_id: &str) -> Result<OrderResponse> {
        let timestamp = self.get_binance_timestamp().await?;
        let now_ms = chrono::Utc::now().timestamp_millis() as u64;
        let params = format!(
            "symbol={}&orderId={}&timestamp={}",
            symbol.replace('/', ""),
            order_id,
            timestamp
        );
        let signature = sign_hmac(self.config.api_secret.expose(), &params)?;
        self.throttle().await;
        let url = format!(
            "{}/api/v3/order?{}&signature={}",
            self.config.base_url, params, signature
        );
        let resp = self
            .http
            .delete(&url)
            .header("X-MBX-APIKEY", self.config.api_key.expose())
            .send()
            .await?;

        let json = parse_exchange_response(resp, "Binance").await?;

        let filled_qty = parse_json_decimal(&json["executedQty"]);
        let avg_price = if filled_qty > Decimal::ZERO {
            parse_json_decimal(&json["cummulativeQuoteQty"]) / filled_qty
        } else {
            Decimal::ZERO
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
            created_at_ms: Some(now_ms),
            updated_at_ms: Some(now_ms),
            deadline_ms: None,
        })
    }

    async fn fetch_balance(&self) -> Result<HashMap<String, Decimal>> {
        self.throttle().await;
        let timestamp = self.get_binance_timestamp().await?;
        let params = format!("timestamp={}", timestamp);
        let signature = sign_hmac(self.config.api_secret.expose(), &params)?;
        let url = format!(
            "{}/api/v3/account?{}&signature={}",
            self.config.base_url, params, signature
        );
        let resp = self
            .http
            .get(&url)
            .header("X-MBX-APIKEY", self.config.api_key.expose())
            .send()
            .await?;

        let json = parse_exchange_response(resp, "Binance").await?;

        let mut balances = HashMap::new();
        if let Some(bals) = json["balances"].as_array() {
            for b in bals {
                let asset = match extract_currency(&b["asset"], "asset", "Binance") {
                Some(a) => a,
                None => continue,
            };
                let free: f64 = b["free"]
                    .as_str()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or_else(|| {
                        let _ = parse_balance_f64(&b["free"], "binance", &asset);
                        0.0
                    });
                let locked: f64 = b["locked"]
                    .as_str()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or_else(|| {
                        let _ = parse_balance_f64(&b["locked"], "binance", &asset);
                        0.0
                    });
                let total = free + locked;
                if total > 0.0 {
                    {
                        let mut seen = self.seen_assets.write().await;
                        seen.insert(asset.clone());
                    }
                    balances.insert(asset, free);
                }
            }
        }
        // H-04: Include zero-balance entries for previously seen assets
        {
            let seen = self.seen_assets.read().await;
            for asset in seen.iter() {
                if !balances.contains_key(asset) {
                    balances.insert(asset.clone(), 0.0);
                }
            }
        }
        Ok(balances
            .into_iter()
            .map(|(k, v)| (k, Decimal::from_f64(v).unwrap_or(Decimal::ZERO)))
            .collect())
    }

    async fn fetch_symbols(&self) -> Result<Vec<String>> {
        let url = format!("{}/api/v3/exchangeInfo", self.config.base_url);
        let resp = self.http.get(&url).send().await?;
        let json: serde_json::Value = resp.json().await?;
        let symbols = json["symbols"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter(|s| s["status"].as_str() == Some("TRADING"))
                    .filter_map(|s| s["symbol"].as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        Ok(symbols)
    }

    async fn fetch_order_status(&self, symbol: &str, order_id: &str) -> Result<OrderResponse> {
        let timestamp = self.get_binance_timestamp().await?;
        let params = format!(
            "symbol={}&orderId={}&timestamp={}",
            symbol.replace('/', ""),
            order_id,
            timestamp
        );
        let signature = sign_hmac(self.config.api_secret.expose(), &params)?;
        self.throttle().await;
        let url = format!(
            "{}/api/v3/order?{}&signature={}",
            self.config.base_url, params, signature
        );
        let resp = self
            .http
            .get(&url)
            .header("X-MBX-APIKEY", self.config.api_key.expose())
            .send()
            .await?;

        let json = parse_exchange_response(resp, "Binance").await?;

        let filled_qty = parse_json_decimal(&json["executedQty"]);
        let avg_price = if filled_qty > Decimal::ZERO {
            let cummulative_quote = parse_json_decimal(&json["cummulativeQuoteQty"]);
            if cummulative_quote == Decimal::ZERO {
                tracing::warn!(
                    order_id,
                    filled_qty = %filled_qty,
                    "Binance fetch_order_status: cummulativeQuoteQty parsed to zero despite filled_qty > 0"
                );
            }
            cummulative_quote / filled_qty
        } else {
            Decimal::ZERO
        };
        // Fee data is not available via GET /api/v3/order endpoint;
        // use fetch_order_status or fills endpoint separately if fee is needed.
        Ok(OrderResponse {
            order_id: extract_order_id(&json["orderId"])?,
            client_order_id: extract_client_order_id(&json["clientOrderId"], "clientOrderId", "Binance"),
            status: json["status"].as_str().unwrap_or("UNKNOWN").to_string(),
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

    async fn health_check(&self) -> Result<()> {
        let url = format!("{}/api/v3/ping", self.config.base_url);
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
        let timestamp = self.get_binance_timestamp().await?;
        let now_ms = chrono::Utc::now().timestamp_millis() as u64;
        let side = if order.side == OrderSide::Buy {
            "BUY"
        } else {
            "SELL"
        };
        let symbol = order.symbol.replace('/', "");
        let mut params = format!(
            "symbol={}&side={}&type=LIMIT&quantity={}&price={}&timeInForce=IOC&timestamp={}",
            symbol, side, order.quantity, price, timestamp
        );
        // Add newClientOrderId for idempotency
        if let Some(ref client_oid) = order.client_order_id {
            if !client_oid.is_empty() {
                params = format!("{}&newClientOrderId={}", params, client_oid);
            }
        }
        let signature = sign_hmac(self.config.api_secret.expose(), &params)?;
        self.throttle().await;
        let url = format!(
            "{}/api/v3/order?{}&signature={}",
            self.config.base_url, params, signature
        );
        let resp = self
            .http
            .post(&url)
            .header("X-MBX-APIKEY", self.config.api_key.expose())
            .header("Content-Type", "application/x-www-form-urlencoded")
            .send()
            .await?;

        let json = parse_exchange_response(resp, "Binance").await?;

        let executed_qty = parse_json_decimal(&json["executedQty"]);
        let cummulative_quote = parse_json_decimal(&json["cummulativeQuoteQty"]);
        let avg_price = if executed_qty > Decimal::ZERO {
            cummulative_quote / executed_qty
        } else {
            Decimal::ZERO
        };
        Ok(OrderResponse {
            order_id: extract_order_id(&json["orderId"])?,
            client_order_id: extract_client_order_id(&json["clientOrderId"], "clientOrderId", "Binance"),
            status: json["status"].as_str().unwrap_or("UNKNOWN").to_string(),
            filled_qty: executed_qty,
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

    /// Kill switch: cancel all open orders using Binance's batch-cancel endpoint.
    /// DELETE /api/v3/openOrders cancels all orders for a given symbol.
    async fn cancel_all_orders(&self, symbols: &[String]) -> Vec<Result<OrderResponse>> {
        let mut results = Vec::new();
        for symbol in symbols {
            let binance_symbol = symbol.replace('/', "");
            match self.cancel_all_for_symbol(&binance_symbol).await {
                Ok(resp) => results.push(Ok(resp)),
                Err(e) => {
                    tracing::error!(
                        "Binance cancel_all_orders failed for {}: {}",
                        binance_symbol,
                        e
                    );
                    results.push(Err(e));
                }
            }
        }
        results
    }

    async fn fetch_order_book(&self, symbol: &str, depth: u32) -> Result<OrderBookSnapshot> {
        let binance_symbol = symbol.replace('/', "");
        let limit = match depth {
            0..=5 => 5,
            6..=10 => 10,
            11..=20 => 20,
            21..=50 => 50,
            51..=100 => 100,
            _ => 500,
        };
        let url = format!(
            "{}/api/v3/depth?symbol={}&limit={}",
            self.config.base_url, binance_symbol, limit
        );
        let resp = self.http.get(&url).send().await?;
        let json: serde_json::Value = resp.json().await?;

        let bids: Vec<OrderBookLevel> = json["bids"]
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

        let asks: Vec<OrderBookLevel> = json["asks"]
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