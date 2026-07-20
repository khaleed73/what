//! Bybit exchange implementation.
//!
//! Implements the `Exchange` trait for Bybit V5 API with HMAC-SHA256
//! request signing. Handles fill data from create responses and falls
//! back to fetch_order_status when fills are not immediately available.

use async_trait::async_trait;
use rust_decimal::Decimal;
use std::collections::HashMap;

use crate::exchange::config::ExchangeConfig;
use crate::exchange::common::*;
use crate::exchange::exchange_trait::*;
use crate::exchange::types::*;
use anyhow::Result;

/// Default receive window in milliseconds for Bybit API requests.
const BYBIT_DEFAULT_RECV_WINDOW_MS: u64 = 5000;

/// Bybit exchange client.
pub struct BybitClient {
    name: String,
    config: ExchangeConfig,
    http: reqwest::Client,
    rate_limiter: RateLimiter,
}

    /// Default HTTP timeout in seconds when not configured.
    const DEFAULT_TIMEOUT_SECS: u64 = 30;
    /// Bybit rate limit in requests per second.
    const BYBIT_RATE_LIMIT: u64 = 20;

impl BybitClient {
    pub fn new(name: String, mut config: ExchangeConfig) -> Result<Self> {
        // Runtime URL override via environment variable.
        // If BYBIT_BASE_URL is set, it takes precedence over the compile-time
        // (or config-provided) URL, allowing testnet↔mainnet switches without
        // recompilation.
        let base_url = if let Ok(env_url) = std::env::var("BYBIT_BASE_URL") {
            if env_url.starts_with("https://") {
                tracing::warn!("BYBIT_BASE_URL env override active — ensure this is intentional");
                env_url
            } else {
                tracing::error!("BYBIT_BASE_URL must use HTTPS, ignoring");
                config.base_url.clone()
            }
        } else {
            config.base_url.clone()
        };
        config.base_url = base_url;
        let timeout_secs = config.http_timeout_secs.unwrap_or(DEFAULT_TIMEOUT_SECS);
        let http = build_http_client(timeout_secs)?;
        Ok(Self {
            name,
            config,
            http,
            rate_limiter: RateLimiter::new(BYBIT_RATE_LIMIT),
        })
    }

    /// Throttle before each private API call.
    #[inline]
    async fn throttle(&self) {
        self.rate_limiter.throttle().await;
    }
}

#[async_trait]
impl Exchange for BybitClient {
    fn name(&self) -> &str {
        &self.name
    }
    fn kind(&self) -> ExchangeType {
        ExchangeType::Bybit
    }

    async fn place_order(&self, order: &OrderRequest) -> Result<OrderResponse> {
        self.place_limit_order(order, Decimal::ZERO).await
    }

    async fn place_limit_order(
        &self,
        order: &OrderRequest,
        price: Decimal,
    ) -> Result<OrderResponse> {
        let timestamp = chrono::Utc::now().timestamp_millis();
        self.throttle().await;
        let side = if order.side == OrderSide::Buy {
            "Buy"
        } else {
            "Sell"
        };
        let symbol = order.symbol.replace('/', "");

        let order_link_id = order.client_order_id.as_deref().unwrap_or("");

        let (_order_type, body) = if price > Decimal::ZERO {
            // Limit order
            let mut b = serde_json::json!({
                "category": "spot",
                "symbol": symbol,
                "side": side,
                "orderType": "Limit",
                "qty": order.quantity.to_string(),
                "price": price.to_string(),
                "timeInForce": "GTC",
            });
            if !order_link_id.is_empty() {
                b["orderLinkId"] = serde_json::Value::String(order_link_id.to_string());
            }
            ("Limit", b)
        } else {
            // Market order
            let mut b = serde_json::json!({
                "category": "spot",
                "symbol": symbol,
                "side": side,
                "orderType": "Market",
                "qty": order.quantity.to_string(),
            });
            if !order_link_id.is_empty() {
                b["orderLinkId"] = serde_json::Value::String(order_link_id.to_string());
            }
            ("Market", b)
        };
 // BYBIT_DEFAULT_RECV_WINDOW_MS: configurable via BYBIT_RECV_WINDOW env var (default 5000ms).
        const BYBIT_DEFAULT_RECV_WINDOW_MS: u64 = 5000;
        let body_str = serde_json::to_string(&body)?;

        // M97 FIX: configurable recvWindow (default 5000ms)
        let recv_window = std::env::var("BYBIT_RECV_WINDOW")
            .ok().and_then(|s| s.parse().ok()).unwrap_or(BYBIT_DEFAULT_RECV_WINDOW_MS);
        let sign_str = format!(
            "{}{}{}{}",
            timestamp,
            self.config.api_key.expose(),
            recv_window,
            body_str
        );
        let signature = sign_hmac(self.config.api_secret.expose(), &sign_str)?;
        let url = format!("{}/v5/order/create", self.config.base_url);
        let resp = self
            .http
            .post(&url)
            .header("X-BAPI-API-KEY", self.config.api_key.expose())
            .header("X-BAPI-SIGN", &signature)
            .header("X-BAPI-SIGN-TYPE", "2")
            .header("X-BAPI-TIMESTAMP", &timestamp.to_string())
            .header("X-BAPI-RECV-WINDOW", &recv_window.to_string())
            .header("Content-Type", "application/json")
            .body(body_str)
            .send()
            .await?;

        let json = parse_exchange_response(resp, "Bybit").await?;

        let result = &json["result"];
        let order_id = extract_order_id(&result["orderId"])?;

        // Parse fill data from the create response if available
        let mut filled_qty = parse_json_decimal(&result["cumExecQty"]);
        let mut avg_price = parse_json_decimal(&result["avgPrice"]);
        let mut fee = parse_json_decimal(&result["cumExecFee"]);

        // If no fill data in the create response, fetch order status to get real fills
        if filled_qty == Decimal::ZERO {
            match self.fetch_order_status(&order.symbol, &order_id).await {
                Ok(status_resp) => {
                    filled_qty = status_resp.filled_qty;
                    avg_price = status_resp.avg_price;
                    fee = status_resp.fee.unwrap_or(Decimal::ZERO);
                }
                Err(e) => {
                    tracing::warn!("Bybit: failed to fetch order status after place: {}", e);
                }
            }
        }

        Ok(OrderResponse {
            order_id,
            client_order_id: order_link_id.to_string(),
            status: if filled_qty > Decimal::ZERO {
                "FILLED".to_string()
            } else {
                "NEW".to_string()
            },
            filled_qty,
            avg_price,
            exchange: self.name.clone(),
            fee: Some(fee),
            fee_currency: None,
            slippage_bps: None,
            created_at_ms: Some(chrono::Utc::now().timestamp_millis() as u64),
            updated_at_ms: Some(chrono::Utc::now().timestamp_millis() as u64),
            deadline_ms: None,
        })
    }

    async fn cancel_order(&self, symbol: &str, order_id: &str) -> Result<OrderResponse> {
        let timestamp = chrono::Utc::now().timestamp_millis();
        self.throttle().await;
        let body = serde_json::json!({
            "category": "spot",
            "symbol": symbol.replace('/', ""),
            "orderId": order_id
        });
        let body_str = serde_json::to_string(&body)?;
        // BYBIT_DEFAULT_RECV_WINDOW_MS: configurable via BYBIT_RECV_WINDOW env var (default 5000ms).
        let recv_window = std::env::var("BYBIT_RECV_WINDOW")
            .ok().and_then(|s| s.parse().ok()).unwrap_or(BYBIT_DEFAULT_RECV_WINDOW_MS);
        let sign_str = format!(
            "{}{}{}{}",
            timestamp,
            self.config.api_key.expose(),
            recv_window,
            body_str
        );
        let signature = sign_hmac(self.config.api_secret.expose(), &sign_str)?;
        let url = format!("{}/v5/order/cancel", self.config.base_url);
        let resp = self
            .http
            .post(&url)
            .header("X-BAPI-API-KEY", self.config.api_key.expose())
            .header("X-BAPI-SIGN", &signature)
            .header("X-BAPI-SIGN-TYPE", "2")
            .header("X-BAPI-TIMESTAMP", &timestamp.to_string())
            .header("X-BAPI-RECV-WINDOW", &recv_window.to_string())
            .header("Content-Type", "application/json")
            .body(body_str)
            .send()
            .await?;

        let json = parse_exchange_response(resp, "Bybit").await?;

        // Note: filled_qty/avg_price from cancel response may reflect
        // partial fills. Caller should use fetch_order_status for
        // authoritative final state.
        let filled_qty = parse_json_decimal(&json["result"]["cumExecQty"]);
        let avg_price = parse_json_decimal(&json["result"]["avgPrice"]);
        let fee = parse_json_decimal(&json["result"]["cumExecFee"]);

        Ok(OrderResponse {
            order_id: order_id.to_string(),
            client_order_id: String::new(),
            status: "CANCELED".to_string(),
            filled_qty,
            avg_price,
            exchange: self.name.clone(),
            fee: if fee > Decimal::ZERO { Some(fee) } else { None },
            fee_currency: None,
            slippage_bps: None,
            created_at_ms: None,
            updated_at_ms: None,
            deadline_ms: None,
        })
    }

    async fn fetch_balance(&self) -> Result<HashMap<String, Decimal>> {
        let timestamp = chrono::Utc::now().timestamp_millis();
        self.throttle().await;
        let query_string = "accountType=UNIFIED";
        let recv_window = std::env::var("BYBIT_RECV_WINDOW")
            .ok().and_then(|s| s.parse().ok()).unwrap_or(5000);
        let sign_str = format!(
            "{}{}{}{}",
            timestamp,
            self.config.api_key.expose(),
            recv_window,
            query_string
        );
        let signature = sign_hmac(self.config.api_secret.expose(), &sign_str)?;
        let url = format!(
            "{}/v5/account/wallet-balance?{}",
            self.config.base_url, query_string
        );
        let resp = self
            .http
            .get(&url)
            .header("X-BAPI-API-KEY", self.config.api_key.expose())
            .header("X-BAPI-SIGN", &signature)
            .header("X-BAPI-SIGN-TYPE", "2")
            .header("X-BAPI-TIMESTAMP", &timestamp.to_string())
            .header("X-BAPI-RECV-WINDOW", &recv_window.to_string())
            .send()
            .await?;

        let json = parse_exchange_response(resp, "Bybit").await?;

        let mut balances = HashMap::new();
        if let Some(accounts) = json["result"]["list"].as_array() {
            for account in accounts {
                if let Some(coins) = account["coin"].as_array() {
                    for coin in coins {
                        // Use walletBalance for total, availableToTrade or free for trading balance.
                        // availableToWithdraw excludes open orders and is NOT the trading balance.
                        let free: f64 = coin["availableToTrade"]
                            .as_str()
                            .or_else(|| coin["free"].as_str())
                            .or_else(|| coin["availableToWithdraw"].as_str())
                            .and_then(|s| s.parse().ok())
                            .unwrap_or_else(|| {
                                let coin_name = coin["coin"].as_str().unwrap_or("?");
                                let _ = parse_balance_f64(&coin["availableToTrade"], "bybit", coin_name);
                                0.0
                            });
                        if free > 0.0 {
                            let coin_name = match extract_currency(&coin["coin"], "coin", "Bybit") {
                    Some(c) => c,
                    None => continue,
                };
                balances.insert(coin_name, free);
                        }
                    }
                }
            }
        }
        Ok(balances
            .into_iter()
            .map(|(k, v)| {
                let bal = balance_f64_to_decimal(v, "bybit", &k);
                (k, bal)
            })
            .collect())
    }

    async fn fetch_symbols(&self) -> Result<Vec<String>> {
        let url = format!(
            "{}/v5/market/instruments-info?category=spot&limit=1000",
            self.config.base_url
        );
        let resp = self.http.get(&url).send().await?;
        let json: serde_json::Value = resp.json().await?;
        let symbols = json["result"]["list"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter(|s| s["status"].as_str() == Some("Trading"))
                    .filter_map(|s| s["symbol"].as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        Ok(symbols)
    }

    async fn fetch_order_status(&self, symbol: &str, order_id: &str) -> Result<OrderResponse> {
        let timestamp = chrono::Utc::now().timestamp_millis();
        self.throttle().await;
        let query_string = format!(
            "category=spot&symbol={}&orderId={}",
            symbol.replace('/', ""),
            order_id
        );
        let recv_window = std::env::var("BYBIT_RECV_WINDOW")
            .ok().and_then(|s| s.parse().ok()).unwrap_or(BYBIT_DEFAULT_RECV_WINDOW_MS);
        let sign_str = format!(
            "{}{}{}{}",
            timestamp,
            self.config.api_key.expose(),
            recv_window,
            query_string
        );
        let signature = sign_hmac(self.config.api_secret.expose(), &sign_str)?;
        let url = format!(
            "{}/v5/order/realtime?{}",
            self.config.base_url, query_string
        );
        let resp = self
            .http
            .get(&url)
            .header("X-BAPI-API-KEY", self.config.api_key.expose())
            .header("X-BAPI-SIGN", &signature)
            .header("X-BAPI-SIGN-TYPE", "2")
            .header("X-BAPI-TIMESTAMP", &timestamp.to_string())
            .header("X-BAPI-RECV-WINDOW", &recv_window.to_string())
            .send()
            .await?;

        let json = parse_exchange_response(resp, "Bybit").await?;

        let result = &json["result"];
        let fee = parse_json_decimal(&result["cumExecFee"]);
        let status = match result["orderStatus"].as_str().unwrap_or("Unknown") {
            "New" | "new" => "NEW".to_string(),
            "PartiallyFilled" | "partiallyFilled" => "PARTIALLY_FILLED".to_string(),
            "Filled" | "filled" => "FILLED".to_string(),
            "Cancelled" | "cancelled" | "Canceled" | "canceled" => "CANCELED".to_string(),
            "Rejected" | "rejected" => "REJECTED".to_string(),
            _ => {
                tracing::warn!(status = %result["orderStatus"], "Bybit: unknown order status");
                "UNKNOWN".to_string()
            }
        };
        Ok(OrderResponse {
            order_id: order_id.to_string(),
            client_order_id: extract_client_order_id(&result["orderLinkId"], "orderLinkId", "Bybit"),
            status,
            filled_qty: parse_json_decimal(&result["cumExecQty"]),
            avg_price: parse_json_decimal(&result["avgPrice"]),
            exchange: self.name.clone(),
            fee: Some(fee),
            fee_currency: None,
            slippage_bps: None,
            created_at_ms: None,
            updated_at_ms: None,
            deadline_ms: None,
        })
    }

    /// Kill switch: cancel all open orders using Bybit's batch-cancel endpoint.
    async fn cancel_all_orders(&self, symbols: &[String]) -> Vec<Result<OrderResponse>> {
        let mut results = Vec::new();
        for symbol in symbols {
            let bybit_symbol = symbol.replace('/', "");
            let timestamp = chrono::Utc::now().timestamp_millis();
        self.throttle().await;
            let body = serde_json::json!({
                "category": "spot",
                "symbol": bybit_symbol,
                "cancelAll": 1
            });
            let body_str = match serde_json::to_string(&body) {
                Ok(s) => s,
                Err(e) => {
                    results.push(Err(anyhow::anyhow!("failed to serialize cancel-all body: {}", e)));
                    continue;
                }
            };
            let recv_window = std::env::var("BYBIT_RECV_WINDOW")
                .ok().and_then(|s| s.parse().ok()).unwrap_or(5000);
            let sign_str = format!(
                "{}{}{}{}",
                timestamp,
                self.config.api_key.expose(),
                recv_window,
                body_str
            );
            let signature = match sign_hmac(self.config.api_secret.expose(), &sign_str) {
                Ok(s) => s,
                Err(e) => {
                    results.push(Err(e));
                    continue;
                }
            };
            let url = format!("{}/v5/order/cancel-all", self.config.base_url);
            match self
                .http
                .post(&url)
                .header("X-BAPI-API-KEY", self.config.api_key.expose())
                .header("X-BAPI-SIGN", &signature)
                .header("X-BAPI-SIGN-TYPE", "2")
                .header("X-BAPI-TIMESTAMP", &timestamp.to_string())
                .header("X-BAPI-RECV-WINDOW", &recv_window.to_string())
                .header("Content-Type", "application/json")
                .body(body_str)
                .send()
                .await
            {
                Ok(resp) => match parse_exchange_response(resp, "Bybit").await {
                    Ok(_) => results.push(Ok(OrderResponse {
                        order_id: format!("cancel-all-{}", bybit_symbol),
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
                    Err(e) => results.push(Err(into_anyhow(e))),
                },
                Err(e) => {
                    results.push(Err(anyhow::anyhow!("Bybit cancel_all HTTP error: {}", e)));
                }
            }
        }
        results
    }

    async fn health_check(&self) -> Result<()> {
        let url = format!("{}/v5/market/time", self.config.base_url);
        let resp = self.http.get(&url).send().await?;
        if resp.status().is_success() {
            Ok(())
        } else {
            anyhow::bail!("Health check failed: {}", resp.status())
        }
    }

    async fn fetch_order_book(&self, symbol: &str, depth: u32) -> Result<OrderBookSnapshot> {
        let bybit_symbol = symbol.replace('/', "");
        let limit = match depth {
            0..=5 => 5,
            6..=10 => 10,
            11..=20 => 20,
            21..=50 => 50,
            _ => 100,
        };
        let url = format!(
            "{}/v5/market/orderbook?category=spot&symbol={}&limit={}",
            self.config.base_url, bybit_symbol, limit
        );
        let resp = self.http.get(&url).send().await?;
        let json: serde_json::Value = resp.json().await?;

        let bids: Vec<OrderBookLevel> = json["result"]["b"]
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

        let asks: Vec<OrderBookLevel> = json["result"]["a"]
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

        let raw_ts = json["result"]["ts"].as_u64().unwrap_or_else(|| {
                tracing::warn!(exchange = "Bybit", raw = %json["result"]["ts"], "orderbook timestamp missing, using Poisson fallback");
                chrono::Utc::now().timestamp_millis() as u64
            });
            let timestamp_us = raw_ts * 1000;

        Ok(OrderBookSnapshot {
            symbol: symbol.to_string(),
            exchange: self.name.clone(),
            bids,
            asks,
            timestamp_us,
        })
    }
}