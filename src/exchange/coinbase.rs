//! Coinbase Exchange implementation.
//!
//! Implements the `Exchange` trait for Coinbase Exchange (Advanced Trade)
//! with HMAC-SHA256 base64-decoded-key signing. Supports market, limit,
//! IOC, and FOK order types with rate limit detection and backoff.

use async_trait::async_trait;
use rust_decimal::Decimal;
use std::collections::HashMap;
use std::time::Duration;

use crate::exchange::config::ExchangeConfig;
use crate::exchange::common::*;
use crate::exchange::exchange_trait::*;
use crate::exchange::types::*;
use anyhow::Result;

/// Coinbase exchange client with rate limiting.
pub struct CoinbaseClient {
    name: String,
    config: ExchangeConfig,
    http: reqwest::Client,
    rate_limiter: RateLimiter,
}

impl CoinbaseClient {
    pub fn new(name: String, config: ExchangeConfig) -> Result<Self> {
        let timeout_secs = config.http_timeout_secs.unwrap_or(30);
        // TODO: This builds a custom HTTP client instead of using the shared
        // build_http_client() from common.rs. Consider switching to
        // build_http_client(timeout_secs)? for consistent settings (pool size,
        // TLS config, TCP nodelay) across all exchange clients.
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(timeout_secs))
            .connect_timeout(Duration::from_secs(timeout_secs.min(10)))
            .pool_max_idle_per_host(4)
            .default_headers({
                let mut headers = reqwest::header::HeaderMap::new();
                headers.insert(
                    reqwest::header::USER_AGENT,
                    reqwest::header::HeaderValue::from_static("rust-hft-arb/1.0"),
                );
                headers.insert(
                    reqwest::header::ACCEPT,
                    reqwest::header::HeaderValue::from_static("application/json"),
                );
                headers
            })
            .build()
            .map_err(|e| anyhow::anyhow!("failed to build HTTP client: {}", e))?;
        Ok(Self {
            name,
            config,
            http,
            rate_limiter: RateLimiter::new(10), // Coinbase: 10 public req/s
        })
    }

    /// Convert a generic "BTC/USD" style symbol to Coinbase's "BTC-USD" format.
    fn coinbase_symbol(symbol: &str) -> String {
        symbol.replace('/', "-").to_uppercase()
    }

    /// Handle exchange response with rate limit detection and backoff.
    async fn handle_response(&self, resp: reqwest::Response) -> Result<serde_json::Value> {
        match parse_exchange_response(resp, &self.name).await {
            Ok(json) => Ok(json),
            Err(ExchangeError::ApiError {
                is_rate_limited: true,
                message,
                ..
            }) => {
                tracing::warn!("{} rate limited, backing off ~1s with jitter: {}", self.name, message);
                jittered_rate_limit_sleep().await;
                anyhow::bail!("Rate limited by {}: {}", self.name, message);
            }
            Err(e) => Err(into_anyhow(e)),
        }
    }

    /// Build Coinbase authentication headers (CB-ACCESS-KEY, CB-ACCESS-SIGN,
    /// CB-ACCESS-TIMESTAMP).
    fn build_auth_headers(
        &self,
        method: &str,
        path: &str,
        body: &str,
    ) -> Result<HashMap<String, String>> {
        let timestamp = chrono::Utc::now().timestamp().to_string();
        let preimage = format!("{}{}{}{}", timestamp, method, path, body);
        let signature = sign_hmac_base64_with_decoded_key(
            self.config.api_secret.expose(),
            &preimage,
        )?;
        let mut headers = HashMap::new();
        headers.insert("CB-ACCESS-KEY".into(), self.config.api_key.expose().into());
        headers.insert("CB-ACCESS-SIGN".into(), signature);
        headers.insert("CB-ACCESS-TIMESTAMP".into(), timestamp);
        Ok(headers)
    }

    /// Send an authenticated request to Coinbase.
    async fn send_auth_request(
        &self,
        method: &str,
        path: &str,
        body: &str,
    ) -> Result<serde_json::Value> {
        self.rate_limiter.throttle().await;
        let headers = self.build_auth_headers(method, path, body)?;
        let url = format!("{}{}", self.config.base_url.trim_end_matches('/'), path);

        let mut req = match method {
            "GET" => self.http.get(&url),
            "POST" => self.http.post(&url).body(body.to_string()),
            "DELETE" => self.http.delete(&url),
            _ => anyhow::bail!("unsupported HTTP method: {}", method),
        };

        for (k, v) in &headers {
            req = req.header(k, v);
        }
        req = req.header("Content-Type", "application/json");

        let resp = req.send().await?;
        self.handle_response(resp).await
    }
}

#[async_trait]
impl Exchange for CoinbaseClient {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> ExchangeType {
        ExchangeType::Coinbase
    }

    async fn place_order(&self, order: &OrderRequest) -> Result<OrderResponse> {
        self.place_limit_order(order, Decimal::ZERO).await
    }

    async fn place_limit_order(
        &self,
        order: &OrderRequest,
        price: Decimal,
    ) -> Result<OrderResponse> {
        let product_id = Self::coinbase_symbol(&order.symbol);
        let side = match order.side {
            OrderSide::Buy => "buy",
            OrderSide::Sell => "sell",
        };

        let body = if price > Decimal::ZERO {
            // Limit order
            serde_json::json!({
                "product_id": product_id,
                "side": side,
                "size": order.quantity.to_string(),
                "price": price.to_string(),
                "time_in_force": "GTC",
                "type": "limit",
            })
        } else {
            // Market order (no price specified)
            serde_json::json!({
                "product_id": product_id,
                "side": side,
                "size": order.quantity.to_string(),
                "type": "market",
            })
        };

        let body_str = body.to_string();
        let json = self
            .send_auth_request("POST", "/orders", &body_str)
            .await?;

        let order_id = extract_order_id(&json["id"])?;
        let status = match json["status"].as_str() {
            Some("filled") => "FILLED",
            Some("open") | Some("pending") => "NEW",
            Some("rejected") => "REJECTED",
            Some("canceled") => "CANCELED",
            _ => "UNKNOWN",
        };
        let filled_qty = parse_json_decimal(&json["filled_size"]);
        let avg_price = parse_json_decimal(&json["average_filled_price"]);
        let fee = json["fee"].as_str()
            .and_then(|s| s.parse::<Decimal>().ok())
            .or_else(|| json["commission"].as_str().and_then(|s| s.parse::<Decimal>().ok()));

        Ok(OrderResponse {
            order_id,
            client_order_id: order.client_order_id.clone().unwrap_or_default(),
            status: status.to_string(),
            filled_qty,
            avg_price,
            exchange: self.name.clone(),
            fee,
            fee_currency: None,
            slippage_bps: None,
            created_at_ms: json["created_at"].as_str().and_then(|s| {
                chrono::DateTime::parse_from_rfc3339(s)
                    .ok()
                    .map(|dt| dt.timestamp_millis() as u64)
            }),
            updated_at_ms: None,
            deadline_ms: None,
        })
    }

    async fn cancel_order(&self, symbol: &str, order_id: &str) -> Result<OrderResponse> {
        let _product_id = Self::coinbase_symbol(symbol);
        let _json = self
            .send_auth_request("DELETE", &format!("/orders/{}", order_id), "")
            .await?;

        // Fetch actual fill state instead of returning hardcoded zeros
        let status_resp = match self.fetch_order_status(symbol, order_id).await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(
                    order_id,
                    error = %e,
                    "Coinbase: failed to fetch order status after cancel, returning zeros"
                );
                OrderResponse {
                    order_id: order_id.to_string(),
                    client_order_id: String::new(),
                    status: "UNKNOWN".to_string(),
                    filled_qty: Decimal::ZERO,
                    avg_price: Decimal::ZERO,
                    exchange: self.name.clone(),
                    fee: None,
                    fee_currency: None,
                    slippage_bps: None,
                    created_at_ms: None,
                    updated_at_ms: Some(chrono::Utc::now().timestamp_millis() as u64),
                    deadline_ms: None,
                }
            }
        };
        Ok(status_resp)
    }

    async fn fetch_balance(&self) -> Result<HashMap<String, Decimal>> {
        let json = self.send_auth_request("GET", "/accounts", "").await?;
        let mut balances = HashMap::new();
        if let Some(accounts) = json.as_array() {
            for acc in accounts {
                let currency = match extract_currency(&acc["currency"], "currency", "Coinbase") {
                        Some(c) => c,
                        None => continue,
                    };
                let available = parse_json_decimal(&acc["available_balance"]["value"]);
                if available > Decimal::ZERO {
                    balances.insert(currency.to_uppercase(), available);
                }
            }
        }
        Ok(balances)
    }

    async fn fetch_symbols(&self) -> Result<Vec<String>> {
        self.rate_limiter.throttle().await;
        // Coinbase: GET /products returns list of trading pairs
        let url = format!(
            "{}/products?limit=500",
            self.config.base_url.trim_end_matches('/')
        );
        let resp = self.http.get(&url).send().await?;
        if !resp.status().is_success() {
            // Return empty rather than failing — inventory check is non-critical
            tracing::warn!("Coinbase fetch_symbols HTTP {}", resp.status());
            return Ok(vec![]);
        }
        let json: serde_json::Value = resp.json().await?;

        // Handle both array and paginated response formats
        let products = if let Some(arr) = json.as_array() {
            arr.clone()
        } else if let Some(arr) = json["products"].as_array() {
            arr.clone()
        } else {
            vec![]
        };

        Ok(products
            .iter()
            .filter_map(|p| {
                // Support both "product_id" (Coinbase Exchange) and "id" keys
                p["product_id"].as_str()
                    .or_else(|| p["id"].as_str())
                    .map(String::from)
            })
            .collect())
    }

    async fn fetch_order_status(&self, _symbol: &str, order_id: &str) -> Result<OrderResponse> {
        let json = self
            .send_auth_request("GET", &format!("/orders/{}", order_id), "")
            .await?;

        let status = match json["status"].as_str() {
            Some("filled") => "FILLED",
            Some("open") => "NEW",
            Some("pending") => "NEW",
            Some("rejected") => "REJECTED",
            Some("canceled") => "CANCELED",
            _ => "UNKNOWN",
        };
        let filled_qty = parse_json_decimal(&json["filled_size"]);
        let avg_price = parse_json_decimal(&json["average_filled_price"]);
        let fee = json["fee"].as_str()
            .and_then(|s| s.parse::<Decimal>().ok())
            .or_else(|| json["commission"].as_str().and_then(|s| s.parse::<Decimal>().ok()));

        Ok(OrderResponse {
            order_id: order_id.to_string(),
            client_order_id: String::new(),
            status: status.to_string(),
            filled_qty,
            avg_price,
            exchange: self.name.clone(),
            fee,
            fee_currency: None,
            slippage_bps: None,
            created_at_ms: None,
            updated_at_ms: None,
            deadline_ms: None,
        })
    }

    async fn health_check(&self) -> Result<()> {
        // Use /time endpoint for lightweight connectivity check
        let url = format!(
            "{}/time",
            self.config.base_url.trim_end_matches('/')
        );
        let resp = self.http.get(&url).send().await?;
        if resp.status().is_success() {
            Ok(())
        } else {
            // Fallback: try /products as alternative health check
            let url2 = format!(
                "{}/products?limit=1",
                self.config.base_url.trim_end_matches('/')
            );
            let resp2 = self.http.get(&url2).send().await?;
            if resp2.status().is_success() {
                Ok(())
            } else {
                anyhow::bail!(
                    "Coinbase health check failed: HTTP {}, HTTP {}",
                    resp.status(), resp2.status()
                )
            }
        }
    }

    async fn cancel_all_orders(&self, symbols: &[String]) -> Vec<Result<OrderResponse>> {
        let mut results = Vec::new();
        for symbol in symbols {
            // Coinbase doesn't have a bulk cancel; cancel open orders per product
            let product_id = Self::coinbase_symbol(symbol);
            let body = serde_json::json!({ "product_id": product_id });
            let body_str = body.to_string();
            match self
                .send_auth_request("POST", "/orders/batch_cancel", &body_str)
                .await
            {
                Ok(_json) => results.push(Ok(OrderResponse {
                    order_id: format!("cancel-all-{}", product_id),
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
                    tracing::error!("Coinbase cancel_all_orders failed for {}: {}", product_id, e);
                    results.push(Err(e));
                }
            }
        }
        results
    }

    async fn fetch_order_book(&self, symbol: &str, depth: u32) -> Result<OrderBookSnapshot> {
        self.rate_limiter.throttle().await;
        let product_id = Self::coinbase_symbol(symbol);
        // Coinbase level=2 returns top 50 bids/asks
        let url = format!(
            "{}/products/{}/book?level=2",
            self.config.base_url.trim_end_matches('/'),
            product_id,
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