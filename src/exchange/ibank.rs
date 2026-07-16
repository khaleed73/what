//! Independent Reserve ("Ibank") exchange implementation.
//!
//! Implements the `Exchange` trait for Independent Reserve
//! (https://www.independentreserve.com) with HMAC-SHA512 signing.
//!
//! Authentication:
//!   Authorization: apikey KEY:SIG:NONCE
//!   SIG = HMAC-SHA512(api_secret, "nonce=" + NONCE + "&apiKey=" + API_KEY)
//!
//! Pair format uses two separate fields: `PrimaryCurrencyCode` and
//! `SecondaryCurrencyCode`. Private endpoints use JSON-RPC-style POST
//! with an empty `{}` body; order fields are embedded in the JSON object.

use async_trait::async_trait;
use base64::Engine;
use rust_decimal::Decimal;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use crate::exchange::config::ExchangeConfig;
use crate::exchange::common::*;
use crate::exchange::exchange_trait::*;
use crate::exchange::types::*;
use anyhow::Result;

/// Independent Reserve exchange client with HMAC-SHA512 auth and rate limiting.
pub struct IbankExchange {
    name: String,
    config: ExchangeConfig,
    http: reqwest::Client,
    rate_limiter: RateLimiter,
    /// Monotonic nonce generator (milliseconds).
    nonce: AtomicU64,
}

impl IbankExchange {
    pub fn new(name: String, config: ExchangeConfig) -> Result<Self> {
        let timeout_secs = config.http_timeout_secs.unwrap_or(30);
        let http = build_http_client(timeout_secs)?;
        let initial_nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        Ok(Self {
            name,
            config,
            http,
            rate_limiter: RateLimiter::new(50),
            nonce: AtomicU64::new(initial_nonce),
        })
    }

    /// Handle exchange response with rate limit detection and backoff.
    async fn handle_response(&self, resp: reqwest::Response) -> Result<serde_json::Value> {
        match parse_exchange_response(resp, "Ibank").await {
            Ok(json) => Ok(json),
            Err(ExchangeError::ApiError {
                is_rate_limited: true,
                message,
                ..
            }) => {
                tracing::warn!("Ibank rate limited, backing off 1s: {}", message);
                tokio::time::sleep(Duration::from_secs(1)).await;
                anyhow::bail!("Rate limited by Ibank: {}", message);
            }
            Err(e) => Err(into_anyhow(e)),
        }
    }

    /// Get the next monotonic nonce.
    fn next_nonce(&self) -> u64 {
        self.nonce.fetch_add(1, Ordering::Relaxed)
    }

    /// Sign a request using HMAC-SHA512.
    ///
    /// Independent Reserve auth spec:
    ///   preimage = "nonce=" + NONCE + "&apiKey=" + API_KEY
    ///   SIG = HMAC-SHA512(api_secret, preimage)
    ///   Header:  Authorization: apikey KEY:SIG:NONCE
    fn sign_request(&self, nonce: u64) -> String {
        let preimage = format!(
            "nonce={}&apiKey={}",
            nonce,
            self.config.api_key.expose()
        );
        let key = ring::hmac::Key::new(
            ring::hmac::HMAC_SHA512,
            self.config.api_secret.expose().as_bytes(),
        );
        let sig = ring::hmac::sign(&key, preimage.as_bytes());
        base64::engine::general_purpose::STANDARD.encode(sig.as_ref())
    }

    /// Build the full `Authorization` header value: `apikey KEY:SIG:NONCE`.
    fn auth_header(&self, nonce: u64) -> String {
        let signature = self.sign_request(nonce);
        format!(
            "apikey {}:{}:{}",
            self.config.api_key.expose(),
            signature,
            nonce
        )
    }

    /// Convert internal symbol (e.g. "BTC/USD") to (primary, secondary) codes.
    fn parse_pair(symbol: &str) -> (String, String) {
        let parts: Vec<&str> = symbol.split('/').collect();
        match parts.as_slice() {
            [base, quote] => (base.to_uppercase(), quote.to_uppercase()),
            _ => (symbol.to_uppercase(), "USD".to_string()),
        }
    }

    /// Map internal OrderSide + OrderType to Independent Reserve OrderType string.
    /// IR uses: "LimitBid", "LimitOffer", "MarketBid", "MarketOffer".
    fn ir_order_type(side: OrderSide, order_type: OrderType) -> String {
        let side_suffix = match side {
            OrderSide::Buy => "Bid",
            OrderSide::Sell => "Offer",
        };
        let prefix = match order_type {
            OrderType::Market => "Market",
            OrderType::Limit => "Limit",
            _ => "Limit",
        };
        format!("{}{}", prefix, side_suffix)
    }

    /// Send a signed POST request (all private IR endpoints are POST).
    async fn send_signed_post(
        &self,
        path: &str,
        body: &serde_json::Value,
    ) -> Result<serde_json::Value> {
        self.rate_limiter.throttle().await;
        let base = self.config.base_url.trim_end_matches('/');
        let nonce = self.next_nonce();
        let url = format!("{}{}", base, path);
        let auth = self.auth_header(nonce);

        let body_str = body.to_string();
        let resp = self
            .http
            .post(&url)
            .header("Authorization", &auth)
            .header("Content-Type", "application/json")
            .body(body_str)
            .send()
            .await?;

        self.handle_response(resp).await
    }

    /// Send a public GET request (unsigned).
    async fn send_public_get(&self, path: &str) -> Result<serde_json::Value> {
        self.rate_limiter.throttle().await;
        let base = self.config.base_url.trim_end_matches('/');
        let url = format!("{}{}", base, path);
        let resp = self.http.get(&url).send().await?;
        let status = resp.status();
        if !status.is_success() {
            anyhow::bail!("Ibank public request failed: HTTP {}", status);
        }
        let text = resp.text().await?;
        let json: serde_json::Value = serde_json::from_str(&text)
            .map_err(|e| anyhow::anyhow!("Ibank parse error: {}", e))?;
        Ok(json)
    }

    /// Build a standard `now_ms` timestamp for `OrderResponse`.
    fn now_ms() -> u64 {
        chrono::Utc::now().timestamp_millis() as u64
    }
}

#[async_trait]
impl Exchange for IbankExchange {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> ExchangeType {
        ExchangeType::Ibank
    }

    // ── Market order ────────────────────────────────────────────────────

    async fn place_order(&self, order: &OrderRequest) -> Result<OrderResponse> {
        let (primary, secondary) = Self::parse_pair(&order.symbol);
        let order_type = Self::ir_order_type(order.side, OrderType::Market);

        let body = serde_json::json!({
            "PrimaryCurrencyCode": primary,
            "SecondaryCurrencyCode": secondary,
            "OrderType": order_type,
            "Volume": order.quantity.to_string(),
        });

        let json = self
            .send_signed_post("/Private/PlaceOrder", &body)
            .await?;

        let order_guid = json["OrderGuid"]
            .as_str()
            .unwrap_or("unknown")
            .to_string();

        Ok(OrderResponse {
            order_id: order_guid,
            client_order_id: order.client_order_id.clone().unwrap_or_default(),
            status: "NEW".to_string(),
            filled_qty: Decimal::ZERO,
            avg_price: Decimal::ZERO,
            exchange: self.name.clone(),
            fee: None,
            fee_currency: None,
            slippage_bps: None,
            created_at_ms: Some(Self::now_ms()),
            updated_at_ms: Some(Self::now_ms()),
            deadline_ms: None,
        })
    }

    // ── Cancel order ────────────────────────────────────────────────────

    async fn cancel_order(&self, _symbol: &str, order_id: &str) -> Result<OrderResponse> {
        let body = serde_json::json!({
            "OrderGuid": order_id,
        });

        self.send_signed_post("/Private/CancelOrder", &body).await?;

        Ok(OrderResponse {
            order_id: order_id.to_string(),
            client_order_id: String::new(),
            status: "CANCELED".to_string(),
            filled_qty: Decimal::ZERO,
            avg_price: Decimal::ZERO,
            exchange: self.name.clone(),
            fee: None,
            fee_currency: None,
            slippage_bps: None,
            created_at_ms: None,
            updated_at_ms: Some(Self::now_ms()),
            deadline_ms: None,
        })
    }

    // ── Balance ─────────────────────────────────────────────────────────

    async fn fetch_balance(&self) -> Result<HashMap<String, Decimal>> {
        // IR uses POST for private endpoints; body is {} (JSON-RPC style)
        let body = serde_json::json!({});
        let json = self
            .send_signed_post("/Private/GetAccounts", &body)
            .await?;

        let mut balances = HashMap::new();

        // IR returns an array of account objects
        let entries = json
            .as_array()
            .cloned()
            .unwrap_or_default();

        for account in &entries {
            let asset = account["AccountCurrencyCode"]
                .as_str()
                .unwrap_or("")
                .to_uppercase();
            let balance = parse_json_decimal(&account["TotalBalance"]);
            if balance > Decimal::ZERO {
                balances.insert(asset, balance);
            }
        }

        Ok(balances)
    }

    // ── Symbols ─────────────────────────────────────────────────────────

    async fn fetch_symbols(&self) -> Result<Vec<String>> {
        // Fetch both primary and secondary currency codes
        let primary_json = match self
            .send_public_get("/Public/GetValidPrimaryCurrencyCodes")
            .await
        {
            Ok(v) => Some(v),
            Err(e) => {
                tracing::warn!(error = %e, "iBank: failed to fetch primary currency codes");
                None
            }
        };

        let secondary_json = match self
            .send_public_get("/Public/GetValidSecondaryCurrencyCodes")
            .await
        {
            Ok(v) => Some(v),
            Err(e) => {
                tracing::warn!(error = %e, "iBank: failed to fetch secondary currency codes");
                None
            }
        };

        let primary_codes: Vec<String> = primary_json
            .and_then(|v| {
                v.as_array()
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|c| c.as_str().map(String::from))
                            .collect()
                    })
            })
            .unwrap_or_default();

        let secondary_codes: Vec<String> = secondary_json
            .and_then(|v| {
                v.as_array()
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|c| c.as_str().map(String::from))
                            .collect()
                    })
            })
            .unwrap_or_else(|| vec!["USD".to_string()]);

        // Cross-product primary × secondary to build all tradeable pairs
        let mut symbols = Vec::new();
        for primary in &primary_codes {
            for secondary in &secondary_codes {
                if primary != secondary {
                    symbols.push(format!("{}/{}", primary, secondary));
                }
            }
        }

        Ok(symbols)
    }

    // ── Order status ────────────────────────────────────────────────────

    async fn fetch_order_status(&self, symbol: &str, order_id: &str) -> Result<OrderResponse> {
        let (primary, secondary) = Self::parse_pair(symbol);

        // IR doesn't have a direct GetOrderDetails for status; we fetch
        // all open orders and filter by OrderGuid.
        let body = serde_json::json!({
            "PrimaryCurrencyCode": primary,
            "SecondaryCurrencyCode": secondary,
        });

        let json = self
            .send_signed_post("/Private/GetOpenOrders", &body)
            .await?;

        // Search for the matching order in the open orders list
        let orders = json.as_array().cloned().unwrap_or_default();
        let found = orders.iter().find(|o| {
            o["OrderGuid"].as_str().map(|g| g == order_id).unwrap_or(false)
        });

        if let Some(order) = found {
            let status_str = order["Status"].as_str().unwrap_or("Unknown");
            let mapped_status = match status_str {
                "Open" => "NEW",
                "PartiallyFilled" => "PARTIALLY_FILLED",
                _ => "UNKNOWN",
            };

            Ok(OrderResponse {
                order_id: order_id.to_string(),
                client_order_id: String::new(),
                status: mapped_status.to_string(),
                filled_qty: parse_json_decimal(&order["VolumeFilled"]),
                avg_price: parse_json_decimal(&order["AvgPrice"]),
                exchange: self.name.clone(),
                fee: None,
                fee_currency: None,
                slippage_bps: None,
                created_at_ms: None,
                updated_at_ms: None,
                deadline_ms: None,
            })
        } else {
            // Order not in open orders — check closed/filled orders
            let closed_body = serde_json::json!({});
            if let Ok(closed_json) = self
                .send_signed_post("/Private/GetClosedOrders", &closed_body)
                .await
            {
                let closed_orders = closed_json.as_array().cloned().unwrap_or_default();
                let closed_found = closed_orders.iter().find(|o| {
                    o["OrderGuid"].as_str().map(|g| g == order_id).unwrap_or(false)
                });

                if let Some(order) = closed_found {
                    let status_str = order["Status"].as_str().unwrap_or("Unknown");
                    let mapped_status = match status_str {
                        "Filled" => "FILLED",
                        "PartiallyFilled" => "PARTIALLY_FILLED",
                        "Cancelled" => "CANCELED",
                        _ => status_str,
                    };

                    return Ok(OrderResponse {
                        order_id: order_id.to_string(),
                        client_order_id: String::new(),
                        status: mapped_status.to_string(),
                        filled_qty: parse_json_decimal(&order["VolumeFilled"]),
                        avg_price: parse_json_decimal(&order["AvgPrice"]),
                        exchange: self.name.clone(),
                        fee: None,
                        fee_currency: None,
                        slippage_bps: None,
                        created_at_ms: None,
                        updated_at_ms: None,
                        deadline_ms: None,
                    });
                }
            }

            // Truly not found — return unknown status rather than guessing FILLED
            Ok(OrderResponse {
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
                updated_at_ms: None,
                deadline_ms: None,
            })
        }
    }

    // ── Health check ────────────────────────────────────────────────────

    async fn health_check(&self) -> Result<()> {
        let url = format!(
            "{}/Public/GetValidPrimaryCurrencyCodes",
            self.config.base_url.trim_end_matches('/')
        );
        let resp = self.http.get(&url).send().await?;
        if resp.status().is_success() {
            Ok(())
        } else {
            anyhow::bail!("Ibank health check failed: HTTP {}", resp.status())
        }
    }

    // ── Cancel all orders ───────────────────────────────────────────────

    async fn cancel_all_orders(&self, symbols: &[String]) -> Vec<Result<OrderResponse>> {
        let mut results = Vec::new();
        for symbol in symbols {
            let (primary, secondary) = Self::parse_pair(symbol);

            let body = serde_json::json!({
                "PrimaryCurrencyCode": primary,
                "SecondaryCurrencyCode": secondary,
            });

            match self
                .send_signed_post("/Private/CancelAllOrders", &body)
                .await
            {
                Ok(_) => results.push(Ok(OrderResponse {
                    order_id: format!("cancel-all-{}", symbol),
                    client_order_id: String::new(),
                    status: "CANCELED".to_string(),
                    filled_qty: Decimal::ZERO,
                    avg_price: Decimal::ZERO,
                    exchange: self.name.clone(),
                    fee: None,
                    fee_currency: None,
                    slippage_bps: None,
                    created_at_ms: Some(Self::now_ms()),
                    updated_at_ms: Some(Self::now_ms()),
                    deadline_ms: None,
                })),
                Err(e) => {
                    tracing::error!("Ibank cancel_all_orders failed for {}: {}", symbol, e);
                    results.push(Err(e));
                }
            }
        }
        results
    }

    // ── Limit order ─────────────────────────────────────────────────────

    async fn place_limit_order(
        &self,
        order: &OrderRequest,
        price: Decimal,
    ) -> Result<OrderResponse> {
        let (primary, secondary) = Self::parse_pair(&order.symbol);
        let order_type = Self::ir_order_type(order.side, OrderType::Limit);

        let body = serde_json::json!({
            "PrimaryCurrencyCode": primary,
            "SecondaryCurrencyCode": secondary,
            "OrderType": order_type,
            "Price": price.to_string(),
            "Volume": order.quantity.to_string(),
        });

        let json = self
            .send_signed_post("/Private/PlaceOrder", &body)
            .await?;

        let order_guid = json["OrderGuid"]
            .as_str()
            .unwrap_or("unknown")
            .to_string();

        Ok(OrderResponse {
            order_id: order_guid,
            client_order_id: order.client_order_id.clone().unwrap_or_default(),
            status: "NEW".to_string(),
            filled_qty: Decimal::ZERO,
            avg_price: Decimal::ZERO,
            exchange: self.name.clone(),
            fee: None,
            fee_currency: None,
            slippage_bps: None,
            created_at_ms: Some(Self::now_ms()),
            updated_at_ms: Some(Self::now_ms()),
            deadline_ms: None,
        })
    }

    // ── Order-type override ─────────────────────────────────────────────

    async fn place_order_with_type(
        &self,
        order: &OrderRequest,
        order_type: OrderType,
        price: Option<Decimal>,
    ) -> Result<OrderResponse> {
        match order_type {
            OrderType::Market => self.place_order(order).await,
            OrderType::Limit => {
                let p = price.ok_or_else(|| {
                    anyhow::anyhow!("Ibank limit order requires a price")
                })?;
                self.place_limit_order(order, p).await
            }
            _ => anyhow::bail!(
                "Order type {:?} not supported on Ibank",
                order_type
            ),
        }
    }

    // ── Order book ──────────────────────────────────────────────────────

    async fn fetch_order_book(&self, symbol: &str, depth: u32) -> Result<OrderBookSnapshot> {
        let (primary, secondary) = Self::parse_pair(symbol);
        let url = format!(
            "{}/Public/GetMarketSummary?primaryCurrencyCode={}&secondaryCurrencyCode={}",
            self.config.base_url.trim_end_matches('/'),
            primary,
            secondary
        );
        let resp = self.http.get(&url).send().await?;
        let status = resp.status();
        if !status.is_success() {
            anyhow::bail!("Ibank orderbook request failed: HTTP {}", status);
        }
        let text = resp.text().await?;
        let json: serde_json::Value = serde_json::from_str(&text)
            .map_err(|e| anyhow::anyhow!("Ibank orderbook parse error: {}", e))?;

        // GetMarketSummary returns a single object (not an array)
        let data = if json.is_array() {
            // If wrapped in array, take first element
            json.get(0).cloned().unwrap_or(json)
        } else {
            json
        };

        // GetMarketSummary provides top-level bid/ask fields
        // For depth, we'd ideally use GetOrderBook, but spec says GetMarketSummary
        let bids = std::iter::once(OrderBookLevel {
            price: parse_json_decimal(&data["CurrentLowestBidPrice"]),
            quantity: parse_json_decimal(&data["CurrentLowestBidVolume"]),
        })
        .take(depth as usize)
        .filter(|l| l.price > Decimal::ZERO)
        .collect();

        let asks = std::iter::once(OrderBookLevel {
            price: parse_json_decimal(&data["CurrentHighestOfferPrice"]),
            quantity: parse_json_decimal(&data["CurrentHighestOfferVolume"]),
        })
        .take(depth as usize)
        .filter(|l| l.price > Decimal::ZERO)
        .collect();

        Ok(OrderBookSnapshot {
            symbol: symbol.to_string(),
            exchange: self.name.clone(),
            bids,
            asks,
            timestamp_us: chrono::Utc::now().timestamp_millis() as u64 * 1000,
        })
    }
}