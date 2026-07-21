//! Dynamic Fee Calculation Module
//!
//! Queries each exchange's REST API for real-time maker/taker fee rates
//! instead of relying solely on static config values. Falls back to config
//! defaults when API queries fail.
//!
//! # Integration
//!
//! ```ignore
//! let fee_mgr = Arc::new(DynamicFeeManager::new(
//!     config_fees,          // HashMap<String, u64> from config
//!     http_client,          // reqwest::Client
//!     execution_pool,       // Arc<HashMap<u16, Arc<dyn PrivateExchangeClient>>>
//!     rest_urls,            // HashMap<u16, String>
//! ));
//! fee_mgr.fetch_all_fees().await;
//! fee_mgr.refresh_periodically(fee_mgr.clone(), 30).await;
//! ```
//!
//! # L-6 Known Limitation: Fee Consistency Across Trade Legs
//!
//! Fees are stored in a `DashMap` and updated asynchronously. If a fee
//! refresh occurs between evaluating leg A and leg B of a multi-leg trade
//! (cross-exchange or triangular), the legs may use inconsistent fee
//! values. This can cause a trade that appeared profitable at evaluation
//! time to be slightly unprofitable after execution.
//!
//! **Recommended mitigation**: Snapshot all relevant fees at the start of
//! each trade evaluation (per-blast) and pass the snapshot to all legs,
//! rather than reading from the `DashMap` on each leg independently.

use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;

use reqwest::Client;
use rust_decimal::Decimal;
use rust_decimal::prelude::ToPrimitive;
use tracing::{debug, info, warn};

use crate::exchange::exchange_name_by_id;
use crate::signer::PrivateExchangeClient;

// ═══════════════════════════════════════════════════════════════════════════
//  FeeSchedule
// ═══════════════════════════════════════════════════════════════════════════

/// Fee rates for a single exchange, cached from API or config.
#[derive(Debug, Clone)]
pub struct FeeSchedule {
    /// Maker fee in basis points (e.g. 10 = 0.10%).
    pub maker_fee_bps: u64,
    /// Taker fee in basis points (e.g. 10 = 0.10%).
    pub taker_fee_bps: u64,
    /// Unix millis timestamp when this schedule was last fetched.
    pub fetched_at: i64,
    /// Where the data came from: "config" or "api".
    pub source: String,
}

// ═══════════════════════════════════════════════════════════════════════════
//  DynamicFeeManager
// ═══════════════════════════════════════════════════════════════════════════

/// Manages per-exchange fee schedules with live API fetching and config
/// fallback.  Uses `DashMap` for lock-free concurrent reads from the hot
/// path.
pub struct DynamicFeeManager {
    /// exchange_id → latest known fee schedule.
    pub fees: dashmap::DashMap<u16, FeeSchedule>,
    /// Static per-exchange taker fee overrides from config.toml,
    /// keyed by exchange name (e.g. "Binance" → 10).
    pub config_fees: HashMap<String, u64>,
    /// HTTP client for REST API calls.
    pub http_client: Client,
    /// Exchange client pool for authenticated requests (signing).
    pub execution_pool: Arc<HashMap<u16, Arc<dyn PrivateExchangeClient>>>,
    /// REST base URLs per exchange id (for unsigned requests).
    pub rest_urls: HashMap<u16, String>,
}

impl DynamicFeeManager {
    /// Create a new `DynamicFeeManager`.
    ///
    /// * `config_fees` — static overrides from `[friction_protections.exchange_taker_fees]`.
    /// * `http_client` — shared `reqwest::Client`.
    /// * `execution_pool` — exchange clients implementing `PrivateExchangeClient`.
    /// * `rest_urls` — exchange id → REST base URL.
    pub fn new(
        config_fees: HashMap<String, u64>,
        http_client: Client,
        execution_pool: Arc<HashMap<u16, Arc<dyn PrivateExchangeClient>>>,
        rest_urls: HashMap<u16, String>,
    ) -> Self {
        Self {
            fees: dashmap::DashMap::new(),
            config_fees,
            http_client,
            execution_pool,
            rest_urls,
        }
    }

    // -----------------------------------------------------------------------
    //  Fetching
    // -----------------------------------------------------------------------

    /// Query every known exchange's fee endpoint and update the cache.
    ///
    /// For exchanges where the API call fails, falls back to the config value
    /// (or a 10 bps default).
    pub async fn fetch_all_fees(&self) {
        // Collect the set of exchange IDs we know about.
        let exchange_ids: Vec<u16> = self
            .execution_pool
            .keys()
            .copied()
            .chain(self.rest_urls.keys().copied())
            .collect();

        for id in &exchange_ids {
            let name = exchange_name_by_id(*id);
            let now = chrono::Utc::now().timestamp_millis();

            let result = match name {
                "Binance" => self.fetch_binance_fees(*id).await,
                "Bybit" => self.fetch_bybit_fees(*id).await,
                "OKX" => self.fetch_okx_fees(*id).await,
                "GateIO" => self.fetch_gateio_fees(*id).await,
                "KuCoin" => self.fetch_kucoin_fees(*id).await,
                "Bitget" => self.fetch_bitget_fees(*id).await,
                "BitMEX" => self.fetch_bitmex_fees(*id).await,
                "Coinbase" => self.fetch_coinbase_fees(*id).await,
                "HTX" => self.fetch_htx_fees(*id).await,
                "Kraken" => {
                    // Kraken's /0/private/TradeVolume requires HMAC-SHA256 auth
                    // which is not available here. Use known defaults directly
                    // (0.25% maker, 0.40% taker) instead of a failing call.
                    debug!(exchange = "Kraken", "Using hardcoded fee defaults (auth required for API)");
                    Some((25, 40))
                }
                "MEXC" => self.fetch_mexc_fees(*id).await,
                _ => {
                    debug!(exchange = name, id, "No API fee fetcher; using config/default");
                    None
                }
            };

            let (maker_bps, taker_bps, source) = match result {
                Some((m, t)) => (m, t, "api".to_string()),
                None => {
                    if let Some(config_fee) = self.config_fees.get(name).copied() {
                        (config_fee, config_fee, "config".to_string())
                    } else {
                        let (dm, dt) = Self::exchange_default_fees(name);
                        (dm, dt, "default".to_string())
                    }
                }
            };

            let schedule = FeeSchedule {
                maker_fee_bps: maker_bps,
                taker_fee_bps: taker_bps,
                fetched_at: now,
                source,
            };

            debug!(
                exchange = name,
                id,
                maker_bps = schedule.maker_fee_bps,
                taker_bps = schedule.taker_fee_bps,
                source = %schedule.source,
                "Fee schedule updated"
            );

            self.fees.insert(*id, schedule);
        }

        info!("Fee schedule refresh complete for {} exchanges", exchange_ids.len());
    }

    // -----------------------------------------------------------------------
    //  Accessors
    // -----------------------------------------------------------------------

    /// Return the cached taker fee in basis points for the given exchange.
    ///
    /// Falls back to config, then to exchange-specific defaults.
    pub fn get_taker_fee_bps(&self, exchange_id: u16) -> u64 {
        if let Some(schedule) = self.fees.get(&exchange_id) {
            return schedule.taker_fee_bps;
        }
        let name = exchange_name_by_id(exchange_id);
        self.config_fees
            .get(name)
            .copied()
            .unwrap_or_else(|| Self::exchange_default_fees(name).1)
    }

    /// Return the cached maker fee in basis points for the given exchange.
    ///
    /// Falls back to config, then to exchange-specific defaults.
    pub fn get_maker_fee_bps(&self, exchange_id: u16) -> u64 {
        if let Some(schedule) = self.fees.get(&exchange_id) {
            return schedule.maker_fee_bps;
        }
        let name = exchange_name_by_id(exchange_id);
        self.config_fees
            .get(name)
            .copied()
            .unwrap_or_else(|| Self::exchange_default_fees(name).0)
    }

    /// Return a summary of all cached fee schedules for logging.
    pub fn get_all_fees_summary(&self) -> Vec<(u16, &str, u64, u64)> {
        self.fees
            .iter()
            .map(|r| {
                let (id, schedule) = r.pair();
                (*id, exchange_name_by_id(*id), schedule.maker_fee_bps, schedule.taker_fee_bps)
            })
            .collect()
    }

    // -----------------------------------------------------------------------
    //  Periodic refresh
    // -----------------------------------------------------------------------

    /// Spawn a background task that refreshes all fee schedules every
    /// `interval_secs` seconds.
    pub async fn refresh_periodically(self: Arc<Self>, interval_secs: u64) {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(interval_secs));
            loop {
                interval.tick().await;
                info!("Periodic fee refresh triggered (every {}s)", interval_secs);
                self.fetch_all_fees().await;
            }
        });
    }

    // ══════════════════════════════════════════════════════════════════════
    //  Per-exchange fetchers
    // ══════════════════════════════════════════════════════════════════════

    /// Binance: `GET /api/v3/account`
    ///
    /// Response contains `makerCommission` and `takerCommission` as
    /// basis-point values (e.g. 10 = 0.10%).
    ///
    /// **Note:** This endpoint requires HMAC-SHA256 authentication.  Since
    /// the `PrivateExchangeClient` trait does not expose the signer, we
    /// attempt an unsigned request and fall back to config defaults on
    /// auth failure.  In production, the caller should seed `config_fees`
    /// with known Binance fee overrides to ensure accuracy.
    async fn fetch_binance_fees(&self, exchange_id: u16) -> Option<(u64, u64)> {
        let url = self.rest_url(exchange_id, "/api/v3/account");

        // Attempt unsigned request — will fail with auth error, but the
        // fallback path in `fetch_all_fees` will use config values.
        match self.unsigned_get_json(&url).await {
            Some(body) => {
                let maker = body.get("makerCommission")?.as_u64()?;
                let taker = body.get("takerCommission")?.as_u64()?;
                Some((maker, taker))
            }
            None => {
                debug!(exchange = "Binance", "Unsigned /account request failed (expected for authenticated endpoint); will use config fallback");
                None
            }
        }
    }

    /// Bybit: `GET /v5/account/fee-rate?category=spot`
    ///
    /// Response: `{ "result": { "list": [{ "makerFeeRate": "0.001", "takerFeeRate": "0.001" }] } }`
    async fn fetch_bybit_fees(&self, exchange_id: u16) -> Option<(u64, u64)> {
        let url = self.rest_url(exchange_id, "/v5/account/fee-rate?category=spot");

        match self.unsigned_get_json(&url).await {
            Some(body) => {
                let list = body
                    .get("result")?
                    .get("list")?
                    .as_array()?;
                if let Some(first) = list.first() {
                    let maker_str = first.get("makerFeeRate")?.as_str()?;
                    let taker_str = first.get("takerFeeRate")?.as_str()?;
                    let maker = bps_from_fraction_str(maker_str);
                    let taker = bps_from_fraction_str(taker_str);
                    return Some((maker, taker));
                }
                None
            }
            None => None,
        }
    }

    /// OKX: `GET /api/v5/account/trading-fees`
    ///
    /// Response: `{ "data": [{ "maker": "0.0008", "taker": "0.001" }] }`
    async fn fetch_okx_fees(&self, exchange_id: u16) -> Option<(u64, u64)> {
        let url = self.rest_url(exchange_id, "/api/v5/account/trading-fees");

        match self.unsigned_get_json(&url).await {
            Some(body) => {
                let data = body.get("data")?.as_array()?;
                if let Some(first) = data.first() {
                    let maker_str = first.get("maker")?.as_str()?;
                    let taker_str = first.get("taker")?.as_str()?;
                    let maker = bps_from_fraction_str(maker_str);
                    let taker = bps_from_fraction_str(taker_str);
                    return Some((maker, taker));
                }
                None
            }
            None => None,
        }
    }

    /// GateIO: `GET /api/v4/spot/fee`
    ///
    /// Response: an array of objects like `[{ "user_id": ..., "taker_fee": "0.002", "maker_fee": "0.002" }]`.
    async fn fetch_gateio_fees(&self, exchange_id: u16) -> Option<(u64, u64)> {
        let url = self.rest_url(exchange_id, "/api/v4/spot/fee");

        match self.unsigned_get_json(&url).await {
            Some(body) => {
                let arr = body.as_array()?;
                if let Some(first) = arr.first() {
                    let maker_str = first.get("maker_fee")?.as_str()?;
                    let taker_str = first.get("taker_fee")?.as_str()?;
                    let maker = bps_from_fraction_str(maker_str);
                    let taker = bps_from_fraction_str(taker_str);
                    return Some((maker, taker));
                }
                None
            }
            None => None,
        }
    }

    /// KuCoin: `GET /api/v1/base-fee`
    ///
    /// Response: `{ "data": { "takerFeeRate": "0.001", "makerFeeRate": "0.001" } }`
    async fn fetch_kucoin_fees(&self, exchange_id: u16) -> Option<(u64, u64)> {
        let url = self.rest_url(exchange_id, "/api/v1/base-fee");

        match self.unsigned_get_json(&url).await {
            Some(body) => {
                let data = body.get("data")?;
                let maker_str = data.get("makerFeeRate")?.as_str()?;
                let taker_str = data.get("takerFeeRate")?.as_str()?;
                let maker = bps_from_fraction_str(maker_str);
                let taker = bps_from_fraction_str(taker_str);
                Some((maker, taker))
            }
            None => None,
        }
    }

    /// Bitget: `GET /api/v2/spot/account/fee-rate`
    ///
    /// Response: `{ "code": "00000", "data": [{ "makerFeeRate": "0.001", "takerFeeRate": "0.001" }] }`
    async fn fetch_bitget_fees(&self, exchange_id: u16) -> Option<(u64, u64)> {
        let url = self.rest_url(exchange_id, "/api/v2/spot/account/fee-rate");

        match self.unsigned_get_json(&url).await {
            Some(body) => {
                // Accept both "data" as array and "data" as object.
                if let Some(data) = body.get("data") {
                    if let Some(arr) = data.as_array() {
                        if let Some(first) = arr.first() {
                            let maker_str = first.get("makerFeeRate")?.as_str()?;
                            let taker_str = first.get("takerFeeRate")?.as_str()?;
                            return Some((bps_from_fraction_str(maker_str), bps_from_fraction_str(taker_str)));
                        }
                    } else if let Some(obj) = data.as_object() {
                        if let (Some(m), Some(t)) = (obj.get("makerFeeRate"), obj.get("takerFeeRate")) {
                            if let (Some(ms), Some(ts)) = (m.as_str(), t.as_str()) {
                                return Some((bps_from_fraction_str(ms), bps_from_fraction_str(ts)));
                            }
                        }
                    }
                }
                None
            }
            None => None,
        }
    }

    /// BitMEX: fee endpoints are unreliable for real-time maker/taker rates.
    /// C-11 fix: Return None to let the config fallback handle it.
    async fn fetch_bitmex_fees(&self, _exchange_id: u16) -> Option<(u64, u64)> {
        None
    }

    /// Coinbase: `GET /fees`
    ///
    /// Coinbase Advanced Trade uses API key auth. We attempt an unsigned
    /// request and parse whatever structure comes back.
    async fn fetch_coinbase_fees(&self, exchange_id: u16) -> Option<(u64, u64)> {
        let url = self.rest_url(exchange_id, "/fees");

        match self.unsigned_get_json(&url).await {
            Some(body) => {
                // Coinbase fee format varies. Try common patterns.
                // Pattern 1: { "taker_fee_rate": "0.006", "maker_fee_rate": "0.004" }
                if let (Some(m), Some(t)) = (
                    body.get("maker_fee_rate").and_then(|v| v.as_str()),
                    body.get("taker_fee_rate").and_then(|v| v.as_str()),
                ) {
                    return Some((bps_from_fraction_str(m), bps_from_fraction_str(t)));
                }
                // Pattern 2: { "data": { "maker_fee_rate": ..., "taker_fee_rate": ... } }
                // The bps_from_fraction_str helper handles both "0.001" and "0.10%" formats.
                if let Some(data) = body.get("data") {
                    if let (Some(m), Some(t)) = (
                        data.get("maker_fee_rate").and_then(|v| v.as_str()),
                        data.get("taker_fee_rate").and_then(|v| v.as_str()),
                    ) {
                        return Some((bps_from_fraction_str(m), bps_from_fraction_str(t)));
                    }
                }
                // Coinbase parse failed — let config/default fallback handle it.
                None
            }
            None => None,
        }
    }

    /// HTX: `GET /v2/account/fee`
    ///
    /// Response: `{ "data": { "symbol": "btcusdt", "maker_fee": 0.002, "taker_fee": 0.002 } }`
    async fn fetch_htx_fees(&self, exchange_id: u16) -> Option<(u64, u64)> {
        let url = self.rest_url(exchange_id, "/v2/account/fee");

        match self.unsigned_get_json(&url).await {
            Some(body) => {
                let data = body.get("data")?;
                // HTX may return the fee as a float or a string.
                let maker = data
                    .get("maker_fee")
                    .and_then(|v| v.as_f64())
                    .map(bps_from_fraction_f64)
                    .or_else(|| {
                        data.get("maker_fee")
                            .and_then(|v| v.as_str())
                            .map(bps_from_fraction_str)
                    })?;
                let taker = data
                    .get("taker_fee")
                    .and_then(|v| v.as_f64())
                    .map(bps_from_fraction_f64)
                    .or_else(|| {
                        data.get("taker_fee")
                            .and_then(|v| v.as_str())
                            .map(bps_from_fraction_str)
                    })?;
                Some((maker, taker))
            }
            None => None,
        }
    }

    /// MEXC: `GET /api/v3/margin/feeRate` (Binance-compatible API)
    ///
    /// Response: `{ "makerCommission": 10, "takerCommission": 10 }` (in bps)
    async fn fetch_mexc_fees(&self, exchange_id: u16) -> Option<(u64, u64)> {
        let url = self.rest_url(exchange_id, "/api/v3/margin/feeRate");

        match self.unsigned_get_json(&url).await {
            Some(body) => {
                // Try Binance-compatible format first.
                if let (Some(m), Some(t)) = (
                    body.get("makerCommission").and_then(|v| v.as_u64()),
                    body.get("takerCommission").and_then(|v| v.as_u64()),
                ) {
                    return Some((m, t));
                }
                // MEXC may also return { "data": { "makerFeeRate": "0.001", "takerFeeRate": "0.001" } }
                if let Some(data) = body.get("data") {
                    if let (Some(m), Some(t)) = (
                        data.get("makerFeeRate").and_then(|v| v.as_str()),
                        data.get("takerFeeRate").and_then(|v| v.as_str()),
                    ) {
                        return Some((bps_from_fraction_str(m), bps_from_fraction_str(t)));
                    }
                    // Also try float format.
                    if let (Some(m), Some(t)) = (
                        data.get("makerFeeRate").and_then(|v| v.as_f64()),
                        data.get("takerFeeRate").and_then(|v| v.as_f64()),
                    ) {
                        return Some((bps_from_fraction_f64(m), bps_from_fraction_f64(t)));
                    }
                }
                // MEXC parse failed — let config/default fallback handle it.
                None
            }
            None => None,
        }
    }

    // -----------------------------------------------------------------------
    //  Internal helpers
    // -----------------------------------------------------------------------

    /// Return exchange-specific default (maker_bps, taker_bps) when no config
    /// or API value is available.
    fn exchange_default_fees(name: &str) -> (u64, u64) {
        match name {
            "Coinbase" => (40, 60),
            "Kraken" => (25, 40),
            "BitMEX" => (8, 8),
            _ => (10, 10),
        }
    }

    /// Build a full URL from an exchange ID and endpoint path.
    fn rest_url(&self, exchange_id: u16, path: &str) -> String {
        let base = self
            .rest_urls
            .get(&exchange_id)
            .map(|s| s.as_str())
            .unwrap_or("");
        let base = base.trim_end_matches('/');
        format!("{}{}", base, path)
    }

    /// Perform an unsigned GET request and parse the JSON body.
    /// Returns `None` on any error (network, parsing, non-2xx).
    async fn unsigned_get_json(&self, url: &str) -> Option<serde_json::Value> {
        let resp = self.http_client.get(url).send().await.ok()?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            warn!(url, %status, body_preview = &body[..body.len().min(200)], "Non-success response fetching fees");
            return None;
        }
        resp.json().await.ok()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  Utility functions
// ═══════════════════════════════════════════════════════════════════════════

/// Convert a fee fraction string (e.g. "0.001" or "0.1%") to basis points.
///
/// - "0.001"   → 10 bps
/// - "0.0002"  → 2 bps
/// - "0.10%"   → 10 bps
/// - "0.40%"   → 40 bps
///
/// C-10 fix: Handle negative fee values (e.g. fee rebates) by clamping
/// to 0 rather than silently wrapping via `as u64`.
fn bps_from_fraction_str(s: &str) -> u64 {
    let trimmed = s.trim();

    // Handle percentage format: "0.10%"
    if let Some(pct_str) = trimmed.strip_suffix('%') {
        if let Ok(pct) = pct_str.parse::<f64>() {
            let bps = (pct * 100.0).round() as i64;
            return bps.max(0) as u64;
        }
    }

    // Handle fraction format: "0.001" = 0.1% = 10 bps
    if let Ok(frac) = trimmed.parse::<f64>() {
        let bps = (frac * 10_000.0).round() as i64;
        return bps.max(0) as u64;
    }

    // Also try Decimal parsing for precision.
    if let Ok(frac) = Decimal::from_str(trimmed) {
        let bps_decimal = frac * Decimal::from(10_000u64);
        if bps_decimal < Decimal::ZERO {
            warn!(input = trimmed, "Negative fee value clamped to 0 bps");
            return 0;
        }
        if let Some(rounded) = bps_decimal.to_u64() {
            return rounded;
        }
    }

    warn!(input = trimmed, "Failed to parse fee string; defaulting to 10 bps");
    10
}

/// Convert a fee fraction f64 (e.g. 0.001) to basis points.
fn bps_from_fraction_f64(f: f64) -> u64 {
    if !f.is_finite() || f < 0.0 { return 0; }
    (f * 10_000.0).round().max(0.0) as u64
}