//! Kraken exchange implementation.
//!
//! Implements the `Exchange` trait for Kraken with nonce-based request
//! signing using HMAC-SHA256 with base64-decoded secret. Supports market,
//! limit, IOC, and FOK order types with rate limit detection and backoff.

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

/// Kraken exchange client with monotonic nonce generator and rate limiting.
pub struct KrakenClient {
    name: String,
    config: ExchangeConfig,
    http: reqwest::Client,
    nonce: KrakenNonce,
    rate_limiter: RateLimiter,
}

impl KrakenClient {
    pub fn new(name: String, config: ExchangeConfig) -> Result<Self> {
        let timeout_secs = config.http_timeout_secs.unwrap_or(30);
        let http = build_http_client(timeout_secs)?;
        Ok(Self {
            name,
            config,
            http,
            nonce: KrakenNonce::new(),
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
                tracing::warn!("{} rate limited, backing off 1s: {}", self.name(), message);
                tokio::time::sleep(Duration::from_secs(1)).await;
                anyhow::bail!("Rate limited by {}: {}", self.name(), message);
            }
            Err(e) => Err(into_anyhow(e)),
        }
    }

    /// Check the Kraken-specific error array in the JSON body.
    /// Kraken returns errors in an `"error"` array even with HTTP 200.
    fn check_kraken_errors(&self, json: &serde_json::Value) -> Result<()> {
        if json["error"]
            .as_array()
            .map(|a| !a.is_empty())
            .unwrap_or(false)
        {
            let errs: Vec<String> = match &json["error"] {
                serde_json::Value::Array(arr) => arr.iter().map(|v| v.to_string()).collect(),
                serde_json::Value::String(s) => vec![s.clone()],
                _ => vec!["unknown error format".to_string()],
            };
            let err_str = errs.join(", ");
            // Check for rate limit errors
            if err_str.contains("Rate limit") || err_str.contains("EAPI:Rate limit") {
                tracing::warn!("Kraken rate limit detected: {}", err_str);
                anyhow::bail!("Rate limited by Kraken: {}", err_str);
            }
            anyhow::bail!("Kraken error: {}", err_str);
        }
        Ok(())
    }

    /// Sign and send a private Kraken API request.
    async fn send_private(&self, path: &str, body: String) -> Result<serde_json::Value> {
        let nonce = self.nonce.next().to_string();
        let body_with_nonce = if body.is_empty() {
            format!("nonce={}", nonce)
        } else {
            format!("nonce={}&{}", nonce, body)
        };
        let signature = sign_kraken(
            self.config.api_secret.expose(),
            path,
            &nonce,
            &body_with_nonce,
        )?;
        let url = format!("{}{}", self.config.base_url, path);
        let resp = self
            .http
            .post(&url)
            .header("API-Key", self.config.api_key.expose())
            .header("API-Sign", &signature)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(body_with_nonce)
            .send()
            .await?;

        let json = self.handle_response(resp).await?;
        self.check_kraken_errors(&json)?;
        Ok(json)
    }
}

/// Derive a deterministic Kraken `userref` (i32) from a client_order_id string.
///
/// H2 FIX (audit): Previously, UUID-style client_order_ids couldn't parse
/// as i64, so userref was always 0 — meaning retries placed duplicate orders.
/// Now we use FNV-1a hashing to derive a deterministic 31-bit positive integer.
fn derive_userref(client_order_id: Option<&String>) -> i64 {
    if let Some(coid) = client_order_id {
        if !coid.is_empty() {
            // Try parsing as integer first (backwards compat)
            if let Ok(n) = coid.parse::<i64>() {
                return n;
            }
            // Hash the string to derive a deterministic userref
            let mut hash: u64 = 0xcbf29ce484222325; // FNV offset basis
            for byte in coid.as_bytes() {
                hash ^= *byte as u64;
                hash = hash.wrapping_mul(0x100000001b3); // FNV prime
            }
            // Mask to 31 bits (positive i32) and ensure non-zero
            let masked = (hash & 0x7FFFFFFF) as i64;
            return if masked == 0 { 1 } else { masked };
        }
    }
    0
}

#[async_trait]
impl Exchange for KrakenClient {
    fn name(&self) -> &str {
        &self.name
    }
    fn kind(&self) -> ExchangeType {
        ExchangeType::Kraken
    }

    async fn place_order(&self, order: &OrderRequest) -> Result<OrderResponse> {
        self.rate_limiter.throttle().await;
        let side = if order.side == OrderSide::Buy {
            "buy"
        } else {
            "sell"
        };
        let pair = order.symbol.replace("BTC/", "XBT/").replace('/', "");

        // H2 FIX: use shared FNV-1a idempotency derivation
        let userref = derive_userref(order.client_order_id.as_ref());
        let mut body = format!(
            "ordertype=market&type={}&volume={}&pair={}",
            side, order.quantity, pair
        );
        if userref != 0 {
            body = format!("{}&userref={}", body, userref);
        }

        let json = self.send_private("/0/private/AddOrder", body).await?;

        let txid = json["result"]["txid"]
            .as_array()
            .and_then(|a| a.first())
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("Kraken: missing txid in place order response"))?
            .to_string();
        let client_order_id = if userref != 0 {
            userref.to_string()
        } else {
            String::new()
        };

        // Fetch order status for fill info
        let mut filled_qty = Decimal::ZERO;
        let mut avg_price = Decimal::ZERO;
        match self.fetch_order_status(&order.symbol, &txid).await {
            Ok(status_resp) => {
                filled_qty = status_resp.filled_qty;
                avg_price = status_resp.avg_price;
            }
            Err(e) => {
                tracing::warn!("Kraken: failed to fetch order status after place: {}", e);
            }
        }

        let now_ms = chrono::Utc::now().timestamp_millis() as u64;
        Ok(OrderResponse {
            order_id: txid,
            client_order_id,
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

    async fn cancel_order(&self, _symbol: &str, order_id: &str) -> Result<OrderResponse> {
        self.rate_limiter.throttle().await;
        let body = format!("txid={}", order_id);
        let _json = self.send_private("/0/private/CancelOrder", body).await?;
        // Kraken cancel response doesn't include fill details; fetch order status
        let (filled_qty, avg_price) = match self.fetch_order_status("", order_id).await {
            Ok(status) => (status.filled_qty, status.avg_price),
            Err(_) => (Decimal::ZERO, Decimal::ZERO),
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
        let json = self
            .send_private("/0/private/Balance", String::new())
            .await?;

        let mut balances = HashMap::new();
        if let Some(result) = json["result"].as_object() {
            for (asset, val) in result {
                let free: f64 = val.as_str().and_then(|s| s.parse().ok()).unwrap_or(0.0);
                if free > 0.0 {
                    balances.insert(asset.to_string(), free);
                }
            }
        }
        Ok(balances
            .into_iter()
            .map(|(k, v)| (k, Decimal::from_f64(v).unwrap_or(Decimal::ZERO)))
            .collect())
    }

    async fn fetch_symbols(&self) -> Result<Vec<String>> {
        let url = format!("{}/0/public/AssetPairs", self.config.base_url);
        let resp = self.http.get(&url).send().await?;
        let json: serde_json::Value = resp.json().await?;
        let symbols: Vec<String> = json["result"]
            .as_object()
            .map(|obj| obj.keys().filter(|k| !k.ends_with(".d")).cloned().collect())
            .unwrap_or_default();
        Ok(symbols)
    }

    async fn fetch_order_status(&self, _symbol: &str, order_id: &str) -> Result<OrderResponse> {
        self.rate_limiter.throttle().await;
        let body = format!("txid={}", order_id);
        let json = self.send_private("/0/private/QueryOrders", body).await?;

        let order_data = &json["result"][order_id];
        let fee = parse_json_decimal(&order_data["fee"]);
        let vol_exec = parse_json_decimal(&order_data["vol_exec"]);
        let vol = parse_json_decimal(&order_data["vol"]);
        let status = match order_data["status"].as_str().unwrap_or("unknown") {
            "pending" | "open" => "NEW".to_string(),
            // Kraken "closed" covers FILLED, PARTIALLY_FILLED (canceled with
            // partial fill), and CANCELED (no fill). Disambiguate via vol_exec.
            "closed" => {
                if vol > Decimal::ZERO && vol_exec == vol {
                    "FILLED".to_string()
                } else if vol_exec > Decimal::ZERO {
                    "PARTIALLY_FILLED".to_string()
                } else {
                    "CANCELED".to_string()
                }
            }
            "canceled" | "cancelled" => {
                if vol_exec > Decimal::ZERO {
                    "PARTIALLY_FILLED".to_string()
                } else {
                    "CANCELED".to_string()
                }
            }
            "expired" => "EXPIRED".to_string(),
            _ => "UNKNOWN".to_string(),
        };
        Ok(OrderResponse {
            order_id: order_id.to_string(),
            client_order_id: String::new(),
            status,
            filled_qty: vol_exec,
            avg_price: parse_json_decimal(if order_data["avg_price"].as_str().is_some() {
                &order_data["avg_price"]
            } else {
                &order_data["price"]
            }),
            exchange: self.name.clone(),
            fee: Some(fee),
            fee_currency: None,
            slippage_bps: None,
            created_at_ms: None,
            updated_at_ms: None,
            deadline_ms: None,
        })
    }

    /// Kill switch: cancel all open orders using Kraken's CancelAll endpoint.
    /// POST /0/private/CancelAll cancels all open orders (optionally filtered by pair).
    async fn cancel_all_orders(&self, symbols: &[String]) -> Vec<Result<OrderResponse>> {
        let mut results = Vec::new();
        for symbol in symbols {
            let pair = symbol.replace("BTC/", "XBT/").replace('/', "");
            let body = format!("pair={}", pair);
            match self.send_private("/0/private/CancelAll", body).await {
                Ok(_json) => results.push(Ok(OrderResponse {
                    order_id: format!("cancel-all-{}", pair),
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
                    tracing::error!("Kraken cancel_all_orders failed for {}: {}", pair, e);
                    results.push(Err(e));
                }
            }
        }
        results
    }

    async fn health_check(&self) -> Result<()> {
        let url = format!("{}/0/public/Time", self.config.base_url);
        let resp = self.http.get(&url).send().await?;
        if resp.status().is_success() {
            Ok(())
        } else {
            anyhow::bail!("Health check failed: {}", resp.status())
        }
    }

    // ── Limit order support ──────────────────────────────────────────────

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
        let pair = order.symbol.replace("BTC/", "XBT/").replace('/', "");

        // H2 FIX: use shared FNV-1a idempotency derivation
        let userref = derive_userref(order.client_order_id.as_ref());
        let mut body = format!(
            "ordertype=limit&type={}&volume={}&pair={}&price={}",
            side, order.quantity, pair, price
        );
        if userref != 0 {
            body = format!("{}&userref={}", body, userref);
        }

        let json = self.send_private("/0/private/AddOrder", body).await?;

        let txid = json["result"]["txid"]
            .as_array()
            .and_then(|a| a.first())
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("Kraken: missing txid in limit order response"))?
            .to_string();
        let client_order_id = if userref != 0 {
            userref.to_string()
        } else {
            String::new()
        };

        // Fetch order status for fill info
        let (filled_qty, avg_price) = match self.fetch_order_status(&order.symbol, &txid).await {
            Ok(status_resp) => (status_resp.filled_qty, status_resp.avg_price),
            Err(e) => {
                tracing::warn!(
                    "Kraken: failed to fetch order status after limit order: {}",
                    e
                );
                (Decimal::ZERO, Decimal::ZERO)
            }
        };

        let now_ms = chrono::Utc::now().timestamp_millis() as u64;
        Ok(OrderResponse {
            order_id: txid,
            client_order_id,
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

    // ── Order-type override: Market / Limit / IOC / FOK ──────────────────

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
        let pair = order.symbol.replace("BTC/", "XBT/").replace('/', "");

        // Kraken: ordertype=market|limit; timeinforce=GTC|IOC|GTD
        // Note: Kraken does not natively support FOK — we approximate it
        // with IOC (immediate-or-cancel) which has similar semantics.
        let (kraken_ordertype, timeinforce_param) = match order_type {
            OrderType::Market => ("market", None),
            OrderType::Limit => match order.time_in_force {
                TimeInForce::IOC => ("limit", Some("IOC")),
                TimeInForce::FOK => {
                    // Kraken has no native FOK; warn and use IOC as closest equivalent
                    tracing::warn!(
                        "Kraken does not support FOK; falling back to IOC for {}",
                        order.symbol
                    );
                    ("limit", Some("IOC"))
                }
                _ => ("limit", Some("GTC")),
            },
            _ => anyhow::bail!(
                "Order type {:?} not supported on {}",
                order_type,
                self.name()
            ),
        };

        // H2 FIX: use shared FNV-1a idempotency derivation
        let userref = derive_userref(order.client_order_id.as_ref());
        let mut body = format!(
            "ordertype={}&type={}&volume={}&pair={}",
            kraken_ordertype, side, order.quantity, pair
        );

        // Price is required for limit orders
        if order_type != OrderType::Market {
            let p = price.ok_or_else(|| {
                anyhow::anyhow!("Limit order requires a price on {}", self.name())
            })?;
            body = format!("{}&price={}", body, p);
        }

        if let Some(tif) = timeinforce_param {
            body = format!("{}&timeinforce={}", body, tif);
        }

        if userref != 0 {
            body = format!("{}&userref={}", body, userref);
        }

        let json = self.send_private("/0/private/AddOrder", body).await?;

        let txid = json["result"]["txid"]
            .as_array()
            .and_then(|a| a.first())
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("Kraken: missing txid in order response"))?
            .to_string();
        let client_order_id = if userref != 0 {
            userref.to_string()
        } else {
            String::new()
        };

        // Fetch order status for fill info
        let (filled_qty, avg_price) = match self.fetch_order_status(&order.symbol, &txid).await {
            Ok(status_resp) => (status_resp.filled_qty, status_resp.avg_price),
            Err(e) => {
                tracing::warn!(
                    "Kraken: failed to fetch order status after place_order_with_type: {}",
                    e
                );
                (Decimal::ZERO, Decimal::ZERO)
            }
        };

        let now_ms = chrono::Utc::now().timestamp_millis() as u64;
        Ok(OrderResponse {
            order_id: txid,
            client_order_id,
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

    // ── Order book with proper depth levels ──────────────────────────────

    async fn fetch_order_book(&self, symbol: &str, depth: u32) -> Result<OrderBookSnapshot> {
        let pair = symbol.replace("BTC/", "XBT/").replace('/', "");
        // Kraken Depth endpoint supports count up to 100 (some pairs support more)
        let count = depth.min(100);
        let url = format!(
            "{}/0/public/Depth?pair={}&count={}",
            self.config.base_url, pair, count
        );
        let resp = self.http.get(&url).send().await?;
        let json: serde_json::Value = resp.json().await?;

        // Kraken wraps result under the pair name
        let result = &json["result"];
        // Find the pair key (it may differ from the input)
        let pair_data = result
            .as_object()
            .and_then(|obj| {
                obj.iter()
                    .find(|(k, _)| k.as_str() != pair && !k.starts_with('_'))
                    .map(|(_, v)| v)
                    .or_else(|| obj.get(&pair))
            })
            .unwrap_or(&serde_json::Value::Null);

        let bids = pair_data["bids"]
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

        let asks = pair_data["asks"]
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
