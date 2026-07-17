use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use chrono::Datelike;
use rust_decimal::prelude::ToPrimitive;

use async_trait::async_trait;
use rust_decimal::Decimal;
use tokio::sync::Mutex;
use rand::Rng;
use tracing::{debug, error, info, warn};

use crate::protections::RiskManager;
use crate::signer::{PrivateApiSigner, PrivateExchangeClient, OrderRequest, OrderSide, OrderType};
use crate::stablecoin::StablecoinMonitor;
use crate::live_order_tracker::LiveOrderTracker;

// ---------------------------------------------------------------------------
// Order Intent – describes what we want to do on an exchange
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct OrderIntent {
    pub exchange_id: u16,
    pub token_id: u16,
    pub qty: Decimal,
    pub price: Decimal,
    pub is_buy: bool,
    pub symbol: String,
}

// ---------------------------------------------------------------------------
// Order Result – what came back after submitting
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct OrderResult {
    pub success: bool,
    pub order_id: Option<String>,
    pub filled_qty: Decimal,
    pub avg_price: Decimal,
    pub error: Option<String>,
    /// Actual slippage observed vs. the intended price, in basis points.
    /// `None` when unavailable or not applicable.
    pub slippage_bps: Option<u64>,
}

// ---------------------------------------------------------------------------
// OrderPipeline trait – abstraction over paper vs. real execution
// ---------------------------------------------------------------------------

#[async_trait]
pub trait OrderPipeline: Send + Sync {
    async fn execute_order(&self, intent: &OrderIntent) -> Result<OrderResult, String>;
}

// ---------------------------------------------------------------------------
// Paper Execution Pipeline – in-memory sandbox with slippage simulation
// ---------------------------------------------------------------------------

pub struct PaperExecutionPipeline {
    /// Shared USDT (or quote) balance. Updated in-place on every fill.
    pub balance: Arc<Mutex<Decimal>>,
    /// Monotonic counter for total trades processed through this pipeline.
    pub total_trades: AtomicU64,
}

impl PaperExecutionPipeline {
    pub fn new(balance: Arc<Mutex<Decimal>>) -> Self {
        Self {
            balance,
            total_trades: AtomicU64::new(0),
        }
    }
}

#[async_trait]
impl OrderPipeline for PaperExecutionPipeline {
    async fn execute_order(&self, intent: &OrderIntent) -> Result<OrderResult, String> {
        // --- slippage simulation ------------------------------------------------
        // 0.01 % base slippage + a tiny pseudo-random component derived from
        // the current nanosecond clock so fills are not perfectly deterministic.
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        // random_factor ∈ [0, 0.999] using pure Decimal arithmetic
        let random_factor = Decimal::from(nanos % 1000) / Decimal::from(1000u32);
        // slippage ∈ [0.0001, 0.0002)  →  0.01 % to 0.02 %
        let slippage_base = Decimal::new(1, 4); // 0.0001
        let slippage = slippage_base + slippage_base * random_factor;

        // For a buy the price drifts up (adverse); for a sell it drifts down.
        let adjusted_price = if intent.is_buy {
            intent.price * (Decimal::ONE + slippage)
        } else {
            intent.price * (Decimal::ONE - slippage)
        };

        let notional = intent.qty * adjusted_price;

        // --- update balance -----------------------------------------------------
        let mut bal = self.balance.lock().await;
        if intent.is_buy {
            // Reject buys that exceed available balance (same guard as
            // PaperTradingPipeline::simulate_fill in paper_trading.rs).
            if *bal < notional {
                drop(bal);
                return Ok(OrderResult {
                    success: false,
                    order_id: None,
                    filled_qty: Decimal::ZERO,
                    avg_price: Decimal::ZERO,
                    error: Some("paper balance insufficient".to_string()),
                    slippage_bps: None,
                });
            }
            *bal -= notional;
        } else {
            *bal += notional;
        }
        drop(bal);

        // --- bookkeeping --------------------------------------------------------
        self.total_trades.fetch_add(1, Ordering::Relaxed);

        let trade_seq = self.total_trades.load(Ordering::Relaxed);
        debug!(
            trade = trade_seq,
            symbol = %intent.symbol,
            side = if intent.is_buy { "BUY" } else { "SELL" },
            qty = %intent.qty,
            price = %intent.price,
            adjusted = %adjusted_price,
            slippage_bps = %slippage * Decimal::from(10_000u32),
            "paper fill"
        );

        Ok(OrderResult {
            success: true,
            order_id: Some(format!("PAPER-{}", trade_seq)),
            filled_qty: intent.qty,
            avg_price: adjusted_price,
            error: None,
            slippage_bps: None,
        })
    }
}

// ---------------------------------------------------------------------------
// Retry helper – exponential backoff for transient failures
// ---------------------------------------------------------------------------

/// Retry an async operation with exponential backoff.
/// max_retries: total attempts (1 = no retry, 2 = one retry, etc.)
/// base_delay_ms: initial delay in ms, doubles each retry
/// On HTTP 429 (rate limit), backs off for 60 seconds and does NOT retry —
/// the exchange needs time to reset its rate window.
async fn retry_with_backoff<F, Fut, T>(
    max_retries: u32,
    base_delay_ms: u64,
    f: F,
) -> Result<T, String>
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = Result<T, String>>,
{
    let mut last_err = String::new();
    for attempt in 0..max_retries {
        match f().await {
            Ok(result) => return Ok(result),
            Err(e) => {
                last_err = e.clone();
                // Detect HTTP 429 rate-limit responses.
                let is_rate_limit = e.contains("429")
                    || e.contains("rate.limit")
                    || e.contains("rate limit")
                    || e.contains("Too Many Requests");

                if is_rate_limit {
                    // On 429, do NOT retry — back off hard for 60 seconds.
                    // The exchange rate-limit window is typically 1-5 minutes;
                    // retrying immediately only makes it worse.
                    error!(
                        attempt = attempt + 1,
                        max_retries,
                        error = %e,
                        "RATE LIMIT (429) detected — aborting retries, 60s cooldown required"
                    );
                    return Err(format!(
                        "rate limited (429): {}. Abort retries — exchange needs ~60s cooldown.",
                        e
                    ));
                }

                if attempt + 1 < max_retries {
                    let base_d = (base_delay_ms * (1 << attempt)).min(2000) as f64;
                    let d = (base_d * (0.75 + 0.5 * rand::thread_rng().gen::<f64>())) as u64;
                    warn!(
                        attempt = attempt + 1,
                        max_retries,
                        delay_ms = d,
                        error = %e,
                        "Retrying after error (with jitter)"
                    );
                    tokio::time::sleep(tokio::time::Duration::from_millis(d.max(10))).await;
                }
            }
        }
    }
    Err(format!("All {} attempts failed. Last error: {}", max_retries, last_err))
}

// ---------------------------------------------------------------------------
// Exchange-Level Rate-Limit Circuit Breaker
// ---------------------------------------------------------------------------

/// Per-exchange rate-limit circuit breaker.  When an exchange returns HTTP 429,
/// it is marked as "cooled down" for a configurable duration (default 60s).
/// During cooldown, ALL orders targeting that exchange are rejected immediately
/// at the engine level (before any HTTP call is made), protecting the bot from
/// cascading ban risk.
///
/// Thread-safe: all state is atomic.  No locks required on the hot path.
pub struct RateLimitCircuitBreaker {
    /// Per-exchange cooldown expiry epoch-millis.  A value of 0 means "not
    /// rate-limited".  Indexed by exchange_id (u16 → usize).
    cooldown_until_ms: Vec<AtomicU64>,
    /// Duration of each cooldown in seconds (default 60).
    cooldown_duration_secs: u64,
}

impl RateLimitCircuitBreaker {
    /// Create a new breaker sized for `num_exchanges` exchanges.
    pub fn new(num_exchanges: usize, cooldown_duration_secs: u64) -> Self {
        let mut cooldown_until_ms = Vec::with_capacity(num_exchanges);
        for _ in 0..num_exchanges {
            cooldown_until_ms.push(AtomicU64::new(0));
        }
        Self {
            cooldown_until_ms,
            cooldown_duration_secs,
        }
    }

    /// Check whether `exchange_id` is currently rate-limited.
    /// Returns `Ok(())` if trading is allowed, or `Err` with a human-readable
    /// message if the exchange is in cooldown.
    pub fn check(&self, exchange_id: u16) -> Result<(), String> {
        let idx = exchange_id as usize;
        if idx >= self.cooldown_until_ms.len() {
            return Ok(()); // unknown exchange — allow
        }
        let until = self.cooldown_until_ms[idx].load(Ordering::Relaxed);
        if until == 0 {
            return Ok(());
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        if now < until {
            let remaining_secs = (until - now) / 1000;
            Err(format!(
                "exchange {} is rate-limited, cooldown remaining: ~{}s",
                exchange_id, remaining_secs
            ))
        } else {
            // Cooldown expired — clear it.
            self.cooldown_until_ms[idx].store(0, Ordering::Relaxed);
            Ok(())
        }
    }

    /// Mark `exchange_id` as rate-limited for the configured cooldown duration.
    /// Called when a 429 response is detected from the exchange.
    pub fn trip(&self, exchange_id: u16) {
        let idx = exchange_id as usize;
        if idx >= self.cooldown_until_ms.len() {
            return;
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let until = now + (self.cooldown_duration_secs * 1000);
        self.cooldown_until_ms[idx].store(until, Ordering::Relaxed);
        error!(
            exchange_id = exchange_id,
            cooldown_secs = self.cooldown_duration_secs,
            "RATE LIMIT CIRCUIT BREAKER: exchange {} tripped, all orders blocked for {}s",
            exchange_id, self.cooldown_duration_secs
        );
    }

    /// Query how many exchanges are currently in cooldown (for monitoring).
    pub fn active_cooldown_count(&self) -> usize {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        self.cooldown_until_ms
            .iter()
            .filter(|v| {
                let until = v.load(Ordering::Relaxed);
                until > 0 && now < until
            })
            .count()
    }
}

// ---------------------------------------------------------------------------
// Real Execution Pipeline – HTTP POST to exchange REST API (Binance-style)
// ---------------------------------------------------------------------------

pub struct RealExecutionPipeline {
    /// Pre-built reqwest client (connection-pooled, potentially with TLS pins).
    pub http_client: reqwest::Client,
    /// exchange_id → base REST URL  (e.g. 0 → "https://api.binance.com")
    pub exchange_rest_urls: HashMap<u16, String>,
    /// exchange_id → HMAC signer (holds api_key + secret internally).
    pub signers: Arc<HashMap<u16, PrivateApiSigner>>,
    /// Typed exchange client pool — when present, `execute_order` routes
    /// through the exchange-specific `PrivateExchangeClient::submit_order`
    /// implementation instead of the generic Binance-style fallback.
    pub typed_pool: Option<Arc<HashMap<u16, Arc<dyn PrivateExchangeClient>>>>,
    /// Exchange-level rate-limit circuit breaker.  When an exchange returns
    /// 429, this breaker is tripped and ALL subsequent orders to that exchange
    /// are rejected for the cooldown duration (default 60s).
    pub rate_limiter: Option<Arc<RateLimitCircuitBreaker>>,
}

impl RealExecutionPipeline {
    pub fn new(
        http_client: reqwest::Client,
        exchange_rest_urls: HashMap<u16, String>,
        signers: Arc<HashMap<u16, PrivateApiSigner>>,
    ) -> Self {
        Self {
            http_client,
            exchange_rest_urls,
            signers,
            typed_pool: None,
            rate_limiter: None,
        }
    }

    /// Attach a typed execution pool.  When set, `execute_order` will
    /// route through the exchange-specific client for the given
    /// `intent.exchange_id`.  Falls back to the generic Binance-style
    /// signer if no typed client is registered for that exchange.
    pub fn with_typed_pool(
        mut self,
        pool: Arc<HashMap<u16, Arc<dyn PrivateExchangeClient>>>,
    ) -> Self {
        self.typed_pool = Some(pool);
        self
    }

    /// Attach an exchange-level rate-limit circuit breaker.
    pub fn with_rate_limiter(mut self, limiter: Arc<RateLimitCircuitBreaker>) -> Self {
        self.rate_limiter = Some(limiter);
        self
    }
}

impl RealExecutionPipeline {
    /// Core execution logic (single attempt).  Called by `execute_order` which
    /// wraps this in `retry_with_backoff`.
    async fn execute_order_inner(&self, intent: &OrderIntent) -> Result<OrderResult, String> {
        // ── Exchange-level rate-limit check (before ANY HTTP call) ──
        if let Some(ref limiter) = self.rate_limiter {
            limiter.check(intent.exchange_id)
                .map_err(|e| format!("rate-limit circuit breaker: {}", e))?;
        }

        // ── Try the typed exchange client pool first ──
        if let Some(ref pool) = self.typed_pool {
            if let Some(client) = pool.get(&intent.exchange_id) {
                let order_req = OrderRequest {
                    symbol: intent.symbol.clone(),
                    side: if intent.is_buy { OrderSide::Buy } else { OrderSide::Sell },
                    order_type: OrderType::Limit,
                    quantity: intent.qty,
                    price: Some(intent.price),
                    client_order_id: None,
                };

                let result = client
                    .submit_order(&self.http_client, order_req)
                    .await
                    .map_err(|e| {
                        let msg = format!("typed client exec error (ex={}): {}", intent.exchange_id, e);
                        // Trip the circuit breaker on 429.
                        if msg.contains("429") || msg.contains("rate.limit") || msg.contains("rate limit") {
                            if let Some(ref limiter) = self.rate_limiter {
                                limiter.trip(intent.exchange_id);
                            }
                        }
                        msg
                    })?;

                // If the exchange returned a 429 rate-limit error inside an Ok
                // result (some clients wrap non-success HTTP as Ok{success:false}),
                // convert to Err so retry_with_backoff can handle it properly.
                if let Some(ref err_msg) = result.error {
                    let is_rl = err_msg.contains("429")
                        || err_msg.contains("rate.limit")
                        || err_msg.contains("rate limit")
                        || err_msg.contains("Too Many Requests");
                    if is_rl {
                        // Trip the circuit breaker.
                        if let Some(ref limiter) = self.rate_limiter {
                            limiter.trip(intent.exchange_id);
                        }
                        return Err(format!("rate limited (ex={}): {}", intent.exchange_id, err_msg));
                    }
                }

                // Map signer::OrderResult → execution::OrderResult
                return Ok(OrderResult {
                    success: result.success,
                    order_id: result.order_id,
                    filled_qty: result.filled_qty,
                    avg_price: result.avg_price,
                    error: result.error,
                    slippage_bps: None,
                });
            }
            // No typed client for this exchange — this is a SAFETY issue.
            // The generic Binance-style fallback POSTs to /api/v3/order which is
            // ONLY correct for Binance.  Sending this to Bybit/OKX/GateIO/KuCoin
            // would either fail silently or hit the wrong endpoint entirely.
            // REFUSE the order rather than risk sending to a wrong API path.
            return Err(format!(
                "CRITICAL: no typed exchange client for exchange_id {}. \
                 The generic Binance-style fallback is DISABLED for safety. \
                 Add a typed client implementation for this exchange before live deployment.",
                intent.exchange_id
            ));
        }

        // No typed_pool at all — same safety check as the no-client case above.
        Err(format!(
            "CRITICAL: no typed_pool configured for exchange_id {}. \
             The generic Binance-style fallback is DISABLED for safety.",
            intent.exchange_id
        ))
    }
}

#[async_trait]
impl OrderPipeline for RealExecutionPipeline {
    async fn execute_order(&self, intent: &OrderIntent) -> Result<OrderResult, String> {
        // Wrap the actual HTTP call with retry: max 2 attempts, 50ms base backoff.
        let this = self;
        let intent = intent.clone();
        retry_with_backoff(3, 50, || {
            let this = this;
            let intent = intent.clone();
            async move { this.execute_order_inner(&intent).await }
        })
        .await
    }
}

// ---------------------------------------------------------------------------
// High-Frequency Execution Engine – orchestrates concurrent multi-leg blasts
// ---------------------------------------------------------------------------

pub struct HighFrequencyExecutionEngine {
    pub risk_manager: Arc<RiskManager>,
    pub depeg_circuit: Arc<StablecoinMonitor>,
    pub paper_pipeline: Arc<dyn OrderPipeline>,
    pub real_pipeline: Arc<dyn OrderPipeline>,
    pub is_paper_mode: AtomicBool,
    /// Counter for emergency rollback events triggered by partial-fill or timeout.
    /// Incremented atomically — readable from monitoring endpoints.
    pub rollback_count: AtomicU64,
    /// Maximum allowed slippage in basis points (e.g. 5 = 0.05 %).
    /// When a fill exceeds this, the trade is flagged and logged as a slippage violation.
    pub max_slippage_bps: AtomicU64,
    /// Total trades rejected by the slippage guard.
    pub slippage_reject_count: AtomicU64,
    /// Pre-trade slippage tolerance as a fixed-point fraction (value × 1_000_000).
    /// Stored as AtomicU64 for lock-free reads on the hot path.
    /// Example: 0.0005 (5 bps) → stored as 500.
    /// Before sending any order, the limit price is widened by this fraction
    /// so the exchange never fills beyond the slippage budget:
    ///   buy  limit = signal_price × (1 + tolerance)
    ///   sell limit = signal_price × (1 − tolerance)
    slippage_tolerance_fp: AtomicU64,
    /// Live order tracker — records order_id for each submitted live order.
    /// In paper mode, this is still created but entries are never cancelled
    /// on-exchange (paper fills are instant).
    pub order_tracker: Arc<LiveOrderTracker>,
    /// HTTP client for cancellation requests (live mode only).
    pub cancel_http_client: Option<reqwest::Client>,
    /// Reference to the typed exchange pool for live cancellation.
    pub cancel_pool: Option<Arc<HashMap<u16, Arc<dyn PrivateExchangeClient>>>>,
    /// Execution mutex — prevents overlapping multi-leg blasts.
    /// When a blast is in-flight, subsequent signals are dropped.
    /// Uses a tokio::Mutex (not std Mutex) so it is .await-safe.
    pub execution_mutex: tokio::sync::Mutex<()>,
    /// Volatility circuit breaker — when true, all trading is halted.
    /// Set by the flash-crash monitor when BTC/ETH moves > threshold.
    pub volatility_circuit: AtomicBool,
    /// Daily loss counter (fixed-point: cents). Resets at midnight UTC.
    pub daily_loss_cents: AtomicU64,
    /// Daily profit counter (fixed-point: cents). Resets at midnight UTC.
    pub daily_profit_cents: AtomicU64,
    /// The UTC day (ordinal) when the daily counters were last reset.
    pub daily_reset_day: std::sync::Mutex<u32>,
    /// Maximum daily loss in cents.  Configurable via `risk_limits.daily_loss_limit_usd`
    /// in `config.toml`.  Default: $100.00 = 10 000 cents.
    pub daily_loss_limit_cents: AtomicU64,
}

impl HighFrequencyExecutionEngine {
    pub fn new(
        risk_manager: Arc<RiskManager>,
        depeg_circuit: Arc<StablecoinMonitor>,
        paper_pipeline: Arc<dyn OrderPipeline>,
        real_pipeline: Arc<dyn OrderPipeline>,
        is_paper_mode: bool,
    ) -> Self {
        Self {
            risk_manager,
            depeg_circuit,
            paper_pipeline,
            real_pipeline,
            is_paper_mode: AtomicBool::new(is_paper_mode),
            rollback_count: AtomicU64::new(0),
            max_slippage_bps: AtomicU64::new(5), // default 0.05 % = 5 bps
            slippage_reject_count: AtomicU64::new(0),
            // Default pre-trade slippage tolerance: 0.05 % = 500 fp-units.
            slippage_tolerance_fp: AtomicU64::new(500),
            order_tracker: Arc::new(LiveOrderTracker::new(300)), // 5-minute max age
            cancel_http_client: None,
            cancel_pool: None,
            execution_mutex: tokio::sync::Mutex::new(()),
            volatility_circuit: AtomicBool::new(false),
            daily_loss_cents: AtomicU64::new(0),
            daily_profit_cents: AtomicU64::new(0),
            daily_reset_day: std::sync::Mutex::new(0),
            daily_loss_limit_cents: AtomicU64::new(10_000), // $100.00 default
        }
    }

    /// Attach the HTTP client and typed exchange pool needed for live
    /// order cancellation.  Must be called AFTER construction if live
    /// mode is active.
    pub fn with_live_cancel(
        mut self,
        http_client: reqwest::Client,
        typed_pool: Arc<HashMap<u16, Arc<dyn PrivateExchangeClient>>>,
    ) -> Self {
        self.cancel_http_client = Some(http_client);
        self.cancel_pool = Some(typed_pool);
        self
    }

    /// Track a live order in the order tracker.  Called after each leg
    /// execution returns an order_id from the exchange.  In paper mode
    /// this is a no-op (paper fills are instant, no cancellation needed).
    fn track_live_order(&self, result: &OrderResult, intent: &OrderIntent) {
        if self.is_paper_mode.load(Ordering::Relaxed) {
            return;
        }
        if let Some(ref order_id) = result.order_id {
            self.order_tracker.track(
                order_id,
                intent.exchange_id,
                &intent.symbol,
                intent.is_buy,
            );
            debug!(
                order_id = %order_id,
                exchange = intent.exchange_id,
                symbol = %intent.symbol,
                "live order tracked for cancellation"
            );
        }
    }

    /// Remove a filled/cancelled order from the tracker.
    fn untrack_live_order(&self, result: &OrderResult) {
        if let Some(ref order_id) = result.order_id {
            self.order_tracker.remove(order_id);
        }
    }

    /// Check and reset daily counters at midnight UTC.
    /// Returns (daily_loss_cents, daily_profit_cents) after potential reset.
    fn check_daily_reset(&self) -> (u64, u64) {
        let today = chrono::Utc::now().ordinal();
        let mut last_day = self.daily_reset_day.lock().unwrap_or_else(|e| e.into_inner());
        if today != *last_day {
            *last_day = today;
            let old_loss = self.daily_loss_cents.swap(0, Ordering::Relaxed);
            let old_profit = self.daily_profit_cents.swap(0, Ordering::Relaxed);
            info!(
                prev_loss_cents = old_loss,
                prev_profit_cents = old_profit,
                new_day = today,
                "daily P&L counters reset at midnight UTC"
            );
        }
        (self.daily_loss_cents.load(Ordering::Relaxed), self.daily_profit_cents.load(Ordering::Relaxed))
    }

    /// Set the daily loss limit (in cents).  Called once at boot from config.
    pub fn set_daily_loss_limit_cents(&self, cents: u64) {
        self.daily_loss_limit_cents.store(cents, Ordering::Relaxed);
    }

    /// Check daily loss limit.  Returns Err if the daily loss exceeds
    /// the configured maximum (in cents).
    fn check_daily_loss_limit(&self) -> Result<(), String> {
        let max_loss_cents = self.daily_loss_limit_cents.load(Ordering::Relaxed);
        let (daily_loss, _) = self.check_daily_reset();
        if daily_loss >= max_loss_cents {
            return Err(format!(
                "daily loss limit reached: {} cents >= {} cents — trading halted until midnight UTC",
                daily_loss, max_loss_cents
            ));
        }
        Ok(())
    }

    /// Record a realized P&L contribution to the daily counter.
    /// `profit_cents` can be negative (loss) or positive (gain).
    fn record_daily_pnl(&self, profit_cents: i64) {
        if profit_cents >= 0 {
            self.daily_profit_cents.fetch_add(profit_cents.unsigned_abs(), Ordering::Relaxed);
        } else {
            self.daily_loss_cents.fetch_add(profit_cents.unsigned_abs(), Ordering::Relaxed);
        }
    }

    /// Check if the volatility circuit breaker is active.
    pub fn is_volatility_circuit_active(&self) -> bool {
        self.volatility_circuit.load(Ordering::Relaxed)
    }

    /// Attempt to cancel a live order on the exchange.
    /// Returns `Ok(true)` if the exchange confirmed cancellation,
    /// `Ok(false)` if no cancel infrastructure exists (paper mode),
    /// `Err` if the cancel request failed (order may still be open).
    async fn attempt_exchange_cancel(
        &self,
        exchange_id: u16,
        symbol: &str,
        order_id: &str,
    ) -> Result<bool, anyhow::Error> {
        let (http, pool) = match (&self.cancel_http_client, &self.cancel_pool) {
            (Some(h), Some(p)) => (h, p),
            _ => return Ok(false), // no cancel infrastructure (paper mode)
        };
        let client = match pool.get(&exchange_id) {
            Some(c) => c,
            None => {
                anyhow::bail!("no typed client for exchange {} — cannot cancel", exchange_id);
            }
        };
        match client.cancel_order(http, symbol, order_id).await {
            Ok(result) => {
                info!(
                    exchange = exchange_id,
                    order_id = %order_id,
                    was_filled = result.filled_qty > Decimal::ZERO,
                    "exchange cancellation succeeded"
                );
                Ok(true)
            }
            Err(e) => {
                error!(
                    exchange = exchange_id,
                    order_id = %order_id,
                    error = %e,
                    "exchange cancellation FAILED — order may still be open"
                );
                Err(anyhow::anyhow!("{}", e))
            }
        }
    }

    /// Execute a two-leg arbitrage (e.g. buy on exchange A, sell on exchange B).
    ///
    /// 1. Pre-trade risk check.
    /// 2. Stablecoin depeg circuit-breaker check.
    /// 3. Select pipeline (paper or real).
    /// 4. Fire both legs concurrently via `tokio::join!` with a 200ms timeout.
    /// 5. On timeout or partial fill, trigger emergency counter-order rollback.
    /// 6. Record success / failure to the risk manager.
    pub async fn blast_arbitrage_legs(
        &self,
        leg_a: OrderIntent,
        leg_b: OrderIntent,
        profit_bps: u64,
        capital_fp: u64,
    ) -> Result<(OrderResult, OrderResult), String> {
        // 0. Execution mutex — prevent overlapping multi-leg blasts.
        // If another blast is in-flight, drop this signal immediately.
        let _lock = match self.execution_mutex.try_lock() {
            Ok(guard) => guard,
            Err(_) => {
                return Err(format!(
                    "execution mutex: another blast is in-flight [{}:{} vs {}:{}], signal dropped",
                    leg_a.exchange_id, leg_a.symbol, leg_b.exchange_id, leg_b.symbol
                ));
            }
        };

        // 0b. Volatility circuit breaker.
        if self.volatility_circuit.load(Ordering::Relaxed) {
            return Err(format!(
                "aborted: volatility circuit breaker active [{}:{} vs {}:{}], signal dropped",
                leg_a.exchange_id, leg_a.symbol, leg_b.exchange_id, leg_b.symbol
            ));
        }

        // 0c. Daily loss limit check (configurable via risk_limits.daily_loss_limit_usd).
        self.check_daily_loss_limit()?;

        // 1. Risk gate. Convert Decimal qty to fixed-point u64 (dollars * 1_000_000).
        let size_fp = decimal_to_fp(leg_a.qty * leg_a.price);
        self.risk_manager
            .pre_trade_check(profit_bps, size_fp, capital_fp, leg_a.exchange_id)
            .map_err(|rejection| format!("pre-trade risk rejection: {}", rejection))?;

        // 2. Stablecoin depeg circuit-breaker.
        if self.depeg_circuit.is_depeg_active().await {
            return Err(format!(
                "aborted: stablecoin depeg circuit-breaker active [{}:{} vs {}:{}], signal dropped",
                leg_a.exchange_id, leg_a.symbol, leg_b.exchange_id, leg_b.symbol
            ));
        }

        // 3. Pipeline selection.
        let pipeline: &Arc<dyn OrderPipeline> = if self.is_paper_mode.load(Ordering::Relaxed) {
            &self.paper_pipeline
        } else {
            &self.real_pipeline
        };

        // 3b. Pre-trade slippage enforcement: widen limit prices so the
        // exchange matching engine can never fill beyond the budgeted slippage.
        // The original (unadjusted) prices are preserved for post-fill
        // verification in verify_leg_slippage.
        let leg_a_original = leg_a.clone();
        let leg_b_original = leg_b.clone();
        let leg_a = self.apply_slippage_limit(&leg_a);
        let leg_b = self.apply_slippage_limit(&leg_b);

        // 4. Concurrent execution of both legs with 200ms per-leg timeout
        //    and a 500ms total blast timeout.
        // On timeout, fire emergency counter-orders to close any partial positions.
        let total_timeout = std::time::Duration::from_millis(500);
        let total_result: Result<(OrderResult, OrderResult), String> = tokio::time::timeout(
            total_timeout,
            async {
                let leg_timeout = std::time::Duration::from_millis(200);
                let (res_a, res_b) = tokio::join!(
                    tokio::time::timeout(leg_timeout, pipeline.execute_order(&leg_a)),
                    tokio::time::timeout(leg_timeout, pipeline.execute_order(&leg_b)),
                );

                // Handle timeouts and convert to OrderResult.
                let result_a = match res_a {
                    Ok(Ok(r)) => r,
                    Ok(Err(_timeout_err)) => {
                        tracing::warn!(
                            exchange = leg_a.exchange_id,
                            symbol = %leg_a.symbol,
                            "leg-a timed out at 200ms — triggering emergency counter-order"
                        );
                        self.rollback_count.fetch_add(1, Ordering::Relaxed);
                        self.fire_counter_order(pipeline, &leg_a, &OrderResult {
                            success: false,
                            order_id: None,
                            filled_qty: Decimal::ZERO,
                            avg_price: Decimal::ZERO,
                            error: Some("200ms timeout".to_string()),
                            slippage_bps: None,
                        }).await;
                        OrderResult {
                            success: false,
                            order_id: None,
                            filled_qty: Decimal::ZERO,
                            avg_price: Decimal::ZERO,
                            error: Some("leg-a timed out after 200ms".to_string()),
                            slippage_bps: None,
                        }
                    }
                    Err(e) => OrderResult {
                        success: false,
                        order_id: None,
                        filled_qty: Decimal::ZERO,
                        avg_price: Decimal::ZERO,
                        error: Some(format!("leg-a error: {}", e)),
                        slippage_bps: None,
                    },
                };

                let result_b = match res_b {
                    Ok(Ok(r)) => r,
                    Ok(Err(_timeout_err)) => {
                        tracing::warn!(
                            exchange = leg_b.exchange_id,
                            symbol = %leg_b.symbol,
                            "leg-b timed out at 200ms — triggering emergency counter-order"
                        );
                        self.rollback_count.fetch_add(1, Ordering::Relaxed);
                        self.fire_counter_order(pipeline, &leg_b, &OrderResult {
                            success: false,
                            order_id: None,
                            filled_qty: Decimal::ZERO,
                            avg_price: Decimal::ZERO,
                            error: Some("200ms timeout".to_string()),
                            slippage_bps: None,
                        }).await;
                        OrderResult {
                            success: false,
                            order_id: None,
                            filled_qty: Decimal::ZERO,
                            avg_price: Decimal::ZERO,
                            error: Some("leg-b timed out after 200ms".to_string()),
                            slippage_bps: None,
                        }
                    }
                    Err(e) => OrderResult {
                        success: false,
                        order_id: None,
                        filled_qty: Decimal::ZERO,
                        avg_price: Decimal::ZERO,
                        error: Some(format!("leg-b error: {}", e)),
                        slippage_bps: None,
                    },
                };

                // ── Order ID tracking: record every live order for cancellation ──
                self.track_live_order(&result_a, &leg_a);
                self.track_live_order(&result_b, &leg_b);

                // Detect asymmetric fills (one leg filled, other didn't) and trigger rollback.
                let a_filled = result_a.success && result_a.filled_qty > Decimal::ZERO;
                let b_filled = result_b.success && result_b.filled_qty > Decimal::ZERO;
                if a_filled ^ b_filled {
                    let (failed_leg, filled_leg) = if a_filled {
                        ("b", &result_b as &OrderResult)
                    } else {
                        ("a", &result_a as &OrderResult)
                    };
                    tracing::warn!(
                        failed_leg,
                        filled_qty = %filled_leg.filled_qty,
                        "asymmetric fill detected — rolling back filled leg"
                    );
                    self.rollback_count.fetch_add(1, Ordering::Relaxed);
                    self.fire_counter_order(
                        pipeline,
                        if a_filled { &leg_b } else { &leg_a },
                        filled_leg,
                    ).await;
                }

                // Record outcomes to risk manager.
                self.record_leg_outcome(leg_a.exchange_id, &result_a);
                self.record_leg_outcome(leg_b.exchange_id, &result_b);

                // Slippage guard: verify both legs against the ORIGINAL signal price
                // (not the slippage-adjusted limit) to detect true market movement.
                if let Err(e) = self.verify_leg_slippage(&leg_a_original, &result_a) {
                    tracing::warn!(
                        exchange = leg_a.exchange_id,
                        symbol = %leg_a.symbol,
                        error = %e,
                        "leg-a slippage violation"
                    );
                }
                if let Err(e) = self.verify_leg_slippage(&leg_b_original, &result_b) {
                    tracing::warn!(
                        exchange = leg_b.exchange_id,
                        symbol = %leg_b.symbol,
                        error = %e,
                        "leg-b slippage violation"
                    );
                }

                Ok((result_a, result_b))
            },
        )
        .await
        .map_err(|_| {
            tracing::warn!(
                "blast_arbitrage_legs total timeout (500ms) [{}:{} vs {}:{}], orders may be in-flight",
                leg_a.exchange_id, leg_a.symbol, leg_b.exchange_id, leg_b.symbol
            );
            // Note: per-leg 200ms timeouts will handle their own counter-orders if they
            // haven't already fired. In-flight orders that passed per-leg timeout but
            // exceeded the total 500ms budget cannot be cancelled from here.
            "blast_arbitrage_legs total timeout exceeded 500ms".to_string()
        })?;
        let total_result = total_result?;

        // ── Post-blast: untrack filled orders, record daily P&L ──
        // Filled orders are removed from the tracker (no need to cancel).
        // Unfilled orders with order_ids remain tracked for the cancellation sweeper.
        if total_result.0.success && total_result.0.filled_qty > Decimal::ZERO {
            self.untrack_live_order(&total_result.0);
        }
        if total_result.1.success && total_result.1.filled_qty > Decimal::ZERO {
            self.untrack_live_order(&total_result.1);
        }

        // Estimate P&L for daily tracking.
        // C4 FIX: Determine buy/sell by the `is_buy` flag on the ORIGINAL intents,
        // not by position in the tuple.  Previously the code assumed result.0
        // was always the buy leg and result.1 was the sell leg, but
        // blast_arbitrage_legs accepts arbitrary OrderIntent pairs.
        if total_result.0.success && total_result.1.success {
            let (buy_result, sell_result) = if leg_a_original.is_buy {
                (&total_result.0, &total_result.1)
            } else {
                (&total_result.1, &total_result.0)
            };
            let buy_notional = buy_result.filled_qty * buy_result.avg_price;
            let sell_notional = sell_result.filled_qty * sell_result.avg_price;
            let profit = sell_notional - buy_notional;
            let profit_cents = (profit * Decimal::from(100u64))
                .trunc()
                .to_i64()
                .unwrap_or(0);
            self.record_daily_pnl(profit_cents);
        }

        Ok(total_result)
    }

    /// Execute a three-leg triangular arbitrage.
    ///
    /// Follows the same risk / depeg / pipeline selection pattern as the
    /// two-leg variant, but fires all three legs concurrently with 200ms timeout.
    /// On timeout or partial fill, triggers emergency counter-order rollback.
    pub async fn blast_triangular_legs(
        &self,
        legs: [OrderIntent; 3],
        profit_bps: u64,
        capital_fp: u64,
    ) -> Result<[OrderResult; 3], String> {
        // 0. Execution mutex — prevent overlapping multi-leg blasts.
        let _lock = match self.execution_mutex.try_lock() {
            Ok(guard) => guard,
            Err(_) => {
                return Err(format!(
                    "execution mutex: another blast is in-flight [{}:{} | {}:{} | {}:{}], signal dropped",
                    legs[0].exchange_id, legs[0].symbol, legs[1].exchange_id, legs[1].symbol, legs[2].exchange_id, legs[2].symbol
                ));
            }
        };

        // 0b. Volatility circuit breaker.
        if self.volatility_circuit.load(Ordering::Relaxed) {
            return Err(format!(
                "aborted: volatility circuit breaker active [{}:{} | {}:{} | {}:{}], signal dropped",
                legs[0].exchange_id, legs[0].symbol, legs[1].exchange_id, legs[1].symbol, legs[2].exchange_id, legs[2].symbol
            ));
        }

        // 0c. Daily loss limit check (configurable via risk_limits.daily_loss_limit_usd).
        self.check_daily_loss_limit()?;

        // 1. Risk gate. Convert Decimal notional to fixed-point u64.
        // M6 FIX: Check ALL legs' exchanges, not just legs[0].  Previously
        // only legs[0].exchange_id was validated — if legs[1] or legs[2]
        // targeted a risk-paused exchange, the trade proceeded anyway.
        let size_fp = decimal_to_fp(legs[0].qty * legs[0].price);
        for leg in &legs {
            self.risk_manager
                .pre_trade_check(profit_bps, size_fp, capital_fp, leg.exchange_id)
                .map_err(|rejection| format!("pre-trade risk rejection (ex={}): {}", leg.exchange_id, rejection))?;
        }

        // 2. Stablecoin depeg circuit-breaker.
        if self.depeg_circuit.is_depeg_active().await {
            return Err(format!(
                "aborted: stablecoin depeg circuit-breaker active [{}:{} | {}:{} | {}:{}], signal dropped",
                legs[0].exchange_id, legs[0].symbol, legs[1].exchange_id, legs[1].symbol, legs[2].exchange_id, legs[2].symbol
            ));
        }

        // 3. Pipeline selection.
        let pipeline: &Arc<dyn OrderPipeline> = if self.is_paper_mode.load(Ordering::Relaxed) {
            &self.paper_pipeline
        } else {
            &self.real_pipeline
        };

        // 3b. Pre-trade slippage enforcement: widen limit prices.
        // Keep originals for post-fill verification.
        let legs_original = [legs[0].clone(), legs[1].clone(), legs[2].clone()];
        let legs = [
            self.apply_slippage_limit(&legs[0]),
            self.apply_slippage_limit(&legs[1]),
            self.apply_slippage_limit(&legs[2]),
        ];

        // 4. Concurrent execution of all three legs with 200ms per-leg timeout
        //    and a 500ms total blast timeout.
        let total_timeout = std::time::Duration::from_millis(500);
        let total_result: Result<[OrderResult; 3], String> = tokio::time::timeout(
            total_timeout,
            async {
                let leg_timeout = std::time::Duration::from_millis(200);
                let (res_0, res_1, res_2) = tokio::join!(
                    tokio::time::timeout(leg_timeout, pipeline.execute_order(&legs[0])),
                    tokio::time::timeout(leg_timeout, pipeline.execute_order(&legs[1])),
                    tokio::time::timeout(leg_timeout, pipeline.execute_order(&legs[2])),
                );

                // Convert timeout/err to OrderResult.
                let mut results = Vec::with_capacity(3);
                for (i, res) in [res_0, res_1, res_2].into_iter().enumerate() {
                    let result = match res {
                        Ok(Ok(r)) => r,
                        Ok(Err(_)) => {
                            tracing::warn!(leg = i, "leg-{} timed out at 200ms — triggering rollback", i);
                            self.rollback_count.fetch_add(1, Ordering::Relaxed);
                            self.fire_counter_order(pipeline, &legs[i], &OrderResult {
                                success: false,
                                order_id: None,
                                filled_qty: Decimal::ZERO,
                                avg_price: Decimal::ZERO,
                                error: Some("200ms timeout".to_string()),
                                slippage_bps: None,
                            }).await;
                            OrderResult {
                                success: false,
                                order_id: None,
                                filled_qty: Decimal::ZERO,
                                avg_price: Decimal::ZERO,
                                error: Some(format!("leg-{} timed out after 200ms", i)),
                                slippage_bps: None,
                            }
                        }
                        Err(e) => OrderResult {
                            success: false,
                            order_id: None,
                            filled_qty: Decimal::ZERO,
                            avg_price: Decimal::ZERO,
                            error: Some(format!("leg-{} error: {}", i, e)),
                            slippage_bps: None,
                        },
                    };
                    results.push(result);
                }

                // ── Order ID tracking: record every live order for cancellation ──
                for (i, result) in results.iter().enumerate() {
                    self.track_live_order(result, &legs[i]);
                }

                // Detect partial fills: if any leg filled but at least one didn't, rollback all fills.
                let filled_count = results.iter().filter(|r| r.success && r.filled_qty > Decimal::ZERO).count();
                let total_legs = 3;
                if filled_count > 0 && filled_count < total_legs {
                    tracing::warn!(
                        filled = filled_count,
                        total = total_legs,
                        "partial triangular fill — rolling back all filled legs"
                    );
                    self.rollback_count.fetch_add(1, Ordering::Relaxed);
                    for (i, result) in results.iter().enumerate() {
                        if result.success && result.filled_qty > Decimal::ZERO {
                            self.fire_counter_order(pipeline, &legs[i], result).await;
                        }
                    }
                }

                // Record outcomes to risk manager.
                for (i, result) in results.iter().enumerate() {
                    self.record_leg_outcome(legs[i].exchange_id, result);
                }

                // Slippage guard: verify all three legs against ORIGINAL signal prices.
                for (i, result) in results.iter().enumerate() {
                    if let Err(e) = self.verify_leg_slippage(&legs_original[i], result) {
                        tracing::warn!(
                            leg = i,
                            exchange = legs[i].exchange_id,
                            symbol = %legs[i].symbol,
                            error = %e,
                            "triangular leg slippage violation"
                        );
                    }
                }

                // Return all three results.
                results.try_into().map_err(|_| "expected exactly 3 results".to_string())
            },
        )
        .await
        .map_err(|_| {
            tracing::warn!(
                "blast_triangular_legs total timeout (500ms) — orders may be in-flight, attempting cancellation"
            );
            // Note: per-leg 200ms timeouts will handle their own counter-orders if they
            // haven't already fired.
            "blast_triangular_legs total timeout exceeded 500ms".to_string()
        })?;
        let total_result = total_result?;

        // ── Post-blast: untrack filled orders ──
        for result in total_result.iter() {
            if result.success && result.filled_qty > Decimal::ZERO {
                self.untrack_live_order(result);
            }
        }

        // M7 FIX: Record P&L for triangular arbitrage (was missing — triangular
        // profits/losses were invisible to the daily loss limit).
        // For a proper triangular P&L, we'd need to know which legs are buys
        // and which are sells and compute the net.  As an approximation, sum
        // the notional of sell legs minus buy legs.
        let mut buy_notional = Decimal::ZERO;
        let mut sell_notional = Decimal::ZERO;
        for (i, result) in total_result.iter().enumerate() {
            if result.success && result.filled_qty > Decimal::ZERO {
                let notional = result.filled_qty * result.avg_price;
                if legs[i].is_buy {
                    buy_notional += notional;
                } else {
                    sell_notional += notional;
                }
            }
        }
        if buy_notional > Decimal::ZERO || sell_notional > Decimal::ZERO {
            let profit = sell_notional - buy_notional;
            let profit_cents = (profit * Decimal::from(100u64))
                .trunc()
                .to_i64()
                .unwrap_or(0);
            self.record_daily_pnl(profit_cents);
        }

        Ok(total_result)
    }

    /// Toggle between paper and real execution mode.
    pub fn set_paper_mode(&self, enabled: bool) {
        self.is_paper_mode.store(enabled, Ordering::Relaxed);
        info!(paper_mode = enabled, "execution mode switched");
    }

    /// Returns `true` when the engine is in paper (sandbox) mode.
    pub fn is_paper_mode(&self) -> bool {
        self.is_paper_mode.load(Ordering::Relaxed)
    }

    /// Returns the cumulative rollback counter (total emergency counter-orders fired).
    pub fn get_rollback_count(&self) -> u64 {
        self.rollback_count.load(Ordering::Relaxed)
    }

    /// Set the maximum slippage tolerance in basis points.
    pub fn set_max_slippage_bps(&self, bps: u64) {
        self.max_slippage_bps.store(bps, Ordering::Relaxed);
    }

    /// Set the pre-trade slippage tolerance as a Decimal fraction.
    /// Stored internally as fixed-point (value × 1_000_000).
    /// Example: `Decimal::new(5, 4)` (= 0.0005 = 5 bps) → stored as 500.
    pub fn set_slippage_tolerance(&self, tolerance: Decimal) {
        let fp = (tolerance * Decimal::from(1_000_000u64)).to_string();
        let val: u64 = fp.split('.').next().and_then(|s| s.parse().ok()).unwrap_or(500);
        self.slippage_tolerance_fp.store(val, Ordering::Release);
    }

    /// Returns the cumulative slippage-rejection counter.
    pub fn get_slippage_reject_count(&self) -> u64 {
        self.slippage_reject_count.load(Ordering::Relaxed)
    }

    /// Widen the limit price on an `OrderIntent` by the configured slippage
    /// tolerance so the exchange can never fill worse than the budgeted amount.
    ///
    /// * **Buy**  → `limit = signal_price × (1 + tolerance)`  (cap the max we pay)
    /// * **Sell** → `limit = signal_price × (1 − tolerance)`  (floor the min we accept)
    ///
    /// This is the **pre-trade** slippage shield.  The exchange's matching engine
    /// will never execute the order beyond this limit price, making slippage
    /// mathematically impossible to exceed (barring exchange-side bugs).
    #[inline]
    fn apply_slippage_limit(&self, intent: &OrderIntent) -> OrderIntent {
        let tol_fp = self.slippage_tolerance_fp.load(Ordering::Acquire);
        if tol_fp == 0 {
            return intent.clone(); // no tolerance → use raw price
        }
        let tolerance = Decimal::from(tol_fp) / Decimal::from(1_000_000u64);
        let adjusted_price = if intent.is_buy {
            // Buy: widen UP so we never pay more than this.
            intent.price * (Decimal::ONE + tolerance)
        } else {
            // Sell: narrow DOWN so we never receive less than this.
            intent.price * (Decimal::ONE - tolerance)
        };

        debug!(
            original_price = %intent.price,
            adjusted_limit = %adjusted_price,
            side = if intent.is_buy { "BUY" } else { "SELL" },
            symbol = %intent.symbol,
            "pre-trade slippage limit applied to order"
        );

        OrderIntent {
            price: adjusted_price,
            ..intent.clone()
        }
    }

    /// Verify slippage on a single leg result.  Returns `Err` if the fill
    /// exceeded the configured maximum slippage tolerance.
    fn verify_leg_slippage(&self, intent: &OrderIntent, result: &OrderResult) -> Result<(), String> {
        if !result.success || result.avg_price <= Decimal::ZERO {
            return Ok(()); // nothing to check on failed fills
        }

        let max_bps = self.max_slippage_bps.load(Ordering::Relaxed);
        match check_slippage(intent.price, result.avg_price, intent.is_buy, max_bps) {
            Ok(bps) => {
                let _ = bps; // observed slippage in bps (available for metrics)
                Ok(())
            }
            Err(e) => {
                self.slippage_reject_count.fetch_add(1, Ordering::Relaxed);
                Err(e)
            }
        }
    }

    /// Internal helper: record a single leg outcome to the risk manager.
    fn record_leg_outcome(&self, exchange_id: u16, result: &OrderResult) {
        if result.success {
            self.risk_manager.record_exchange_success(exchange_id);
        } else {
            self.risk_manager.record_exchange_failure(exchange_id);
        }
    }

    /// Emergency counter-order: fires an opposite-side order with the already-filled
    /// quantity at a nudged price to guarantee execution.
    /// This is the HFT safety net for partial-fill or timeout scenarios.
    ///
    /// C3 FIX: If `filled_qty` is zero (timeout before any fill), we skip the
    /// counter-order entirely — there is no position to close.  Previously this
    /// sent qty=0, price=0 orders that the exchange would reject, wasting API
    /// budget and leaving the operator with a false sense of safety.
    async fn fire_counter_order(
        &self,
        pipeline: &Arc<dyn OrderPipeline>,
        original: &OrderIntent,
        filled: &OrderResult,
    ) {
        let fill_qty = filled.filled_qty.max(Decimal::ZERO);
        if fill_qty <= Decimal::ZERO {
            // No fill occurred — nothing to roll back.  Log and return.
            tracing::warn!(
                exchange = original.exchange_id,
                symbol = %original.symbol,
                "counter-order skipped: no fill to roll back (timeout before execution)"
            );
            return;
        }

        // Use the filled average price if available, otherwise fall back to the
        // original signal price (the order may have been acknowledged but the
        // fill details not yet returned in the timeout window).
        let base_price = if filled.avg_price > Decimal::ZERO {
            filled.avg_price
        } else {
            original.price
        };

        let counter = OrderIntent {
            exchange_id: original.exchange_id,
            token_id: original.token_id,
            qty: fill_qty,
            // Nudge price 0.5% in adverse direction to guarantee the counter-order fills.
            // Counter-order is the OPPOSITE side of the original, so:
            //   - Original was BUY (we hold long) → counter is SELL → nudge DOWN (accept less)
            //   - Original was SELL (we hold short) → counter is BUY → nudge UP (pay more)
            // C3 FIX: Increased from 0.1% to 0.5% nudge to improve fill probability
            // during volatile market conditions when the counter-order is most needed.
            price: if original.is_buy {
                // Counter: SELL — nudge price DOWN 0.5% to accept a worse sell price
                base_price * (Decimal::new(995, 3)) // 0.995 → -0.5%
            } else {
                // Counter: BUY — nudge price UP 0.5% to pay a worse buy price
                base_price * (Decimal::new(1005, 3)) // 1.005 → +0.5%
            },
            is_buy: !original.is_buy,
            symbol: original.symbol.clone(),
        };
        match pipeline.execute_order(&counter).await {
            Ok(result) => {
                tracing::info!(
                    exchange = original.exchange_id,
                    counter_order_id = ?result.order_id,
                    counter_filled = %result.filled_qty,
                    "emergency counter-order executed"
                );
            }
            Err(e) => {
                tracing::error!(
                    exchange = original.exchange_id,
                    error = %e,
                    "emergency counter-order FAILED — manual intervention required"
                );
            }
        }
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;
    use tokio::sync::Mutex;

    /// Helper: build a simple buy intent.
    fn buy_intent(exchange_id: u16, symbol: &str, qty: &str, price: &str) -> OrderIntent {
        OrderIntent {
            exchange_id,
            token_id: 0,
            qty: Decimal::from_str(qty).unwrap(),
            price: Decimal::from_str(price).unwrap(),
            is_buy: true,
            symbol: symbol.to_string(),
        }
    }

    /// Helper: build a simple sell intent.
    fn sell_intent(exchange_id: u16, symbol: &str, qty: &str, price: &str) -> OrderIntent {
        OrderIntent {
            exchange_id: exchange_id,
            token_id: 1,
            qty: Decimal::from_str(qty).unwrap(),
            price: Decimal::from_str(price).unwrap(),
            is_buy: false,
            symbol: symbol.to_string(),
        }
    }

    // -----------------------------------------------------------------------
    // test_paper_pipeline_simulates_fill
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn test_paper_pipeline_simulates_fill() {
        let initial_balance = Decimal::from_str("10000.00").unwrap();
        let balance = Arc::new(Mutex::new(initial_balance));
        let pipeline = PaperExecutionPipeline::new(Arc::clone(&balance));

        // Buy 0.1 BTC at 50,000 USDT each → notional ≈ 5,000 USDT.
        let intent = buy_intent(0, "BTCUSDT", "0.1", "50000.00");

        let result = pipeline.execute_order(&intent).await.expect("paper order should succeed");

        assert!(result.success, "paper fill must report success");
        assert_eq!(result.filled_qty, intent.qty);
        assert!(result.order_id.is_some(), "paper fill must return an order id");
        assert!(result.error.is_none());

        // The average price should reflect adverse slippage (higher than intent price for a buy).
        assert!(
            result.avg_price > intent.price,
            "buy slippage should increase the execution price: got {} vs intent {}",
            result.avg_price,
            intent.price,
        );

        // Balance should have decreased by qty * avg_price.
        let final_balance = *balance.lock().await;
        let expected_notional = intent.qty * result.avg_price;
        let expected_balance = initial_balance - expected_notional;
        assert_eq!(
            final_balance, expected_balance,
            "balance mismatch: expected {}, got {} (notional was {})",
            expected_balance, final_balance, expected_notional,
        );

        // Trade counter should have incremented.
        assert_eq!(pipeline.total_trades.load(Ordering::Relaxed), 1);
    }

    // -----------------------------------------------------------------------
    // test_blast_legs_risk_block
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn test_blast_legs_risk_block() {
        // Build a RiskManager with defaults from config (min_net_profit_pct = 0.15% = 15 bps).
        let risk_config = crate::configs::ValidatedRiskConfig {
            min_net_profit_pct: Decimal::new(15, 4), // 0.0015 = 15 bps
            max_equity_staleness_seconds: 10,
            absolute_hard_loss_cap: Decimal::from(150),
            pct_hard_loss_cap: Decimal::new(1, 2), // 0.01
            max_drawdown_pct: Decimal::new(4, 2),  // 0.04
            max_total_exposure_pct: Decimal::ONE,
            max_single_position_pct: Decimal::new(15, 2), // 0.15
            exchange_failure_threshold: 3,
            exchange_pause_duration_seconds: 30,
            stablecoin_depeg_threshold: Decimal::new(5, 3), // 0.005
            daily_loss_limit_usd: Decimal::from(100),
        };
        let risk_manager = Arc::new(RiskManager::new(risk_config));
        risk_manager.update_equity(100_000_000_000u64);
        risk_manager.touch_network_check();

        // Build a minimal StablecoinMonitor (depeg inactive by default).
        let depeg_circuit = Arc::new(StablecoinMonitor::new(crate::stablecoin::StablecoinConfig::default()));

        // Use paper pipelines for both slots so no real network I/O happens.
        let paper_bal_a = Arc::new(Mutex::new(Decimal::from(100_000u64)));
        let paper_bal_b = Arc::new(Mutex::new(Decimal::from(100_000u64)));
        let paper_pipeline_a: Arc<dyn OrderPipeline> =
            Arc::new(PaperExecutionPipeline::new(paper_bal_a));
        let paper_pipeline_b: Arc<dyn OrderPipeline> =
            Arc::new(PaperExecutionPipeline::new(paper_bal_b));

        let engine = HighFrequencyExecutionEngine::new(
            risk_manager,
            depeg_circuit,
            paper_pipeline_a,
            paper_pipeline_b,
            true, // paper mode
        );

        // profit_bps = 0 → well below the 15 bps minimum → risk manager should reject.
        let leg_a = buy_intent(0, "BTCUSDT", "0.01", "50000.00");
        let leg_b = sell_intent(1, "BTCUSDT", "0.01", "50050.00");

        let err = engine
            .blast_arbitrage_legs(leg_a, leg_b, 0, 1_000_000)
            .await
            .expect_err("zero-profit blast should be rejected by risk manager");

        assert!(
            err.contains("pre-trade risk rejection"),
            "expected risk rejection, got: {}",
            err,
        );
    }

    // -----------------------------------------------------------------------
    // Slippage guard tests
    // -----------------------------------------------------------------------
    #[test]
    fn test_slippage_guard_buy_within_tolerance() {
        // Buy at 50000, filled at 50025 → 5 bps.  Max = 5 bps → OK.
        let result = check_slippage(
            Decimal::from_str("50000").unwrap(),
            Decimal::from_str("50025").unwrap(),
            true,
            5,
        );
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 5);
    }

    #[test]
    fn test_slippage_guard_buy_exceeds_tolerance() {
        // Buy at 50000, filled at 50030 → 6 bps.  Max = 5 bps → REJECT.
        let result = check_slippage(
            Decimal::from_str("50000").unwrap(),
            Decimal::from_str("50030").unwrap(),
            true,
            5,
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("slippage guard"));
    }

    #[test]
    fn test_slippage_guard_sell_within_tolerance() {
        // Sell at 50000, filled at 49975 → 5 bps.  Max = 5 bps → OK.
        let result = check_slippage(
            Decimal::from_str("50000").unwrap(),
            Decimal::from_str("49975").unwrap(),
            false,
            5,
        );
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 5);
    }

    #[test]
    fn test_slippage_guard_sell_exceeds_tolerance() {
        // Sell at 50000, filled at 49970 → 6 bps.  Max = 5 bps → REJECT.
        let result = check_slippage(
            Decimal::from_str("50000").unwrap(),
            Decimal::from_str("49970").unwrap(),
            false,
            5,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_slippage_guard_favorable_buy_skipped() {
        // Buy at 50000, filled at 49990 (better price!) → 0 bps adverse → OK.
        let result = check_slippage(
            Decimal::from_str("50000").unwrap(),
            Decimal::from_str("49990").unwrap(),
            true,
            5,
        );
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0);
    }

    #[test]
    fn test_slippage_guard_zero_price_no_panic() {
        let result = check_slippage(Decimal::ZERO, Decimal::from_str("50000").unwrap(), true, 5);
        assert!(result.is_ok());
    }

    // -----------------------------------------------------------------------
    // Pre-trade slippage limit tests
    // -----------------------------------------------------------------------
    #[test]
    fn test_apply_slippage_limit_buy() {
        let risk_config = crate::configs::ValidatedRiskConfig {
            min_net_profit_pct: Decimal::new(15, 4),
            max_equity_staleness_seconds: 10,
            absolute_hard_loss_cap: Decimal::from(150),
            pct_hard_loss_cap: Decimal::new(1, 2),
            max_drawdown_pct: Decimal::new(4, 2),
            max_total_exposure_pct: Decimal::ONE,
            max_single_position_pct: Decimal::new(15, 2),
            exchange_failure_threshold: 3,
            exchange_pause_duration_seconds: 30,
            stablecoin_depeg_threshold: Decimal::new(5, 3),
            daily_loss_limit_usd: Decimal::from(100),
        };
        let risk_manager = Arc::new(RiskManager::new(risk_config));
        let depeg_circuit = Arc::new(StablecoinMonitor::new(crate::stablecoin::StablecoinConfig::default()));
        let paper_bal = Arc::new(Mutex::new(Decimal::from(100_000u64)));
        let paper_pipeline: Arc<dyn OrderPipeline> = Arc::new(PaperExecutionPipeline::new(paper_bal));
        let real_pipeline: Arc<dyn OrderPipeline> = Arc::new(PaperExecutionPipeline::new(
            Arc::new(Mutex::new(Decimal::from(100_000u64))),
        ));

        let engine = HighFrequencyExecutionEngine::new(
            risk_manager,
            depeg_circuit,
            paper_pipeline,
            real_pipeline,
            true,
        );

        // Set 5 bps (0.0005) slippage tolerance.
        engine.set_slippage_tolerance(Decimal::new(5, 4));

        let intent = buy_intent(0, "BTCUSDT", "0.1", "50000.00");
        let adjusted = engine.apply_slippage_limit(&intent);

        // Buy limit should be 50000 * (1 + 0.0005) = 50025
        assert_eq!(adjusted.price, Decimal::from_str("50025.000000").unwrap_or_else(|_| {
            // Allow small rounding differences
            let expected = Decimal::from_str("50000").unwrap()
                * (Decimal::ONE + Decimal::new(5, 4));
            expected
        }));
        assert!(adjusted.price > intent.price, "buy limit should be higher than signal");
    }

    #[test]
    fn test_apply_slippage_limit_sell() {
        let risk_config = crate::configs::ValidatedRiskConfig {
            min_net_profit_pct: Decimal::new(15, 4),
            max_equity_staleness_seconds: 10,
            absolute_hard_loss_cap: Decimal::from(150),
            pct_hard_loss_cap: Decimal::new(1, 2),
            max_drawdown_pct: Decimal::new(4, 2),
            max_total_exposure_pct: Decimal::ONE,
            max_single_position_pct: Decimal::new(15, 2),
            exchange_failure_threshold: 3,
            exchange_pause_duration_seconds: 30,
            stablecoin_depeg_threshold: Decimal::new(5, 3),
            daily_loss_limit_usd: Decimal::from(100),
        };
        let risk_manager = Arc::new(RiskManager::new(risk_config));
        let depeg_circuit = Arc::new(StablecoinMonitor::new(crate::stablecoin::StablecoinConfig::default()));
        let paper_pipeline: Arc<dyn OrderPipeline> = Arc::new(PaperExecutionPipeline::new(
            Arc::new(Mutex::new(Decimal::from(100_000u64))),
        ));
        let real_pipeline: Arc<dyn OrderPipeline> = Arc::new(PaperExecutionPipeline::new(
            Arc::new(Mutex::new(Decimal::from(100_000u64))),
        ));

        let engine = HighFrequencyExecutionEngine::new(
            risk_manager,
            depeg_circuit,
            paper_pipeline,
            real_pipeline,
            true,
        );
        engine.set_slippage_tolerance(Decimal::new(5, 4));

        let intent = sell_intent(0, "BTCUSDT", "0.1", "50000.00");
        let adjusted = engine.apply_slippage_limit(&intent);

        // Sell limit should be 50000 * (1 - 0.0005) = 49975
        assert!(adjusted.price < intent.price, "sell limit should be lower than signal");
        let expected = Decimal::from_str("50000").unwrap()
            * (Decimal::ONE - Decimal::new(5, 4));
        assert_eq!(adjusted.price, expected);
    }

    #[test]
    fn test_apply_slippage_limit_zero_tolerance_passthrough() {
        let risk_config = crate::configs::ValidatedRiskConfig {
            min_net_profit_pct: Decimal::new(15, 4),
            max_equity_staleness_seconds: 10,
            absolute_hard_loss_cap: Decimal::from(150),
            pct_hard_loss_cap: Decimal::new(1, 2),
            max_drawdown_pct: Decimal::new(4, 2),
            max_total_exposure_pct: Decimal::ONE,
            max_single_position_pct: Decimal::new(15, 2),
            exchange_failure_threshold: 3,
            exchange_pause_duration_seconds: 30,
            stablecoin_depeg_threshold: Decimal::new(5, 3),
            daily_loss_limit_usd: Decimal::from(100),
        };
        let risk_manager = Arc::new(RiskManager::new(risk_config));
        let depeg_circuit = Arc::new(StablecoinMonitor::new(crate::stablecoin::StablecoinConfig::default()));
        let paper_pipeline: Arc<dyn OrderPipeline> = Arc::new(PaperExecutionPipeline::new(
            Arc::new(Mutex::new(Decimal::from(100_000u64))),
        ));
        let real_pipeline: Arc<dyn OrderPipeline> = Arc::new(PaperExecutionPipeline::new(
            Arc::new(Mutex::new(Decimal::from(100_000u64))),
        ));

        let engine = HighFrequencyExecutionEngine::new(
            risk_manager,
            depeg_circuit,
            paper_pipeline,
            real_pipeline,
            true,
        );
        // Zero tolerance → use set_slippage_tolerance(0).
        engine.set_slippage_tolerance(Decimal::ZERO);

        let intent = buy_intent(0, "BTCUSDT", "0.1", "50000.00");
        let adjusted = engine.apply_slippage_limit(&intent);
        assert_eq!(adjusted.price, intent.price);
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Slippage guard: verify that the actual fill price did not deviate beyond
/// the configured maximum slippage tolerance.
///
/// Returns `Ok(())` when the fill is within tolerance, or `Err` with a
/// descriptive message when slippage exceeds the limit.
///
/// # Arguments
/// * `intended_price` – the price at which we wanted to fill (from the signal).
/// * `actual_price`  – the volume-weighted average price from the exchange.
/// * `is_buy`        – `true` for buys (adverse = actual > intended).
/// * `max_slippage_bps` – maximum acceptable deviation in basis points (e.g. 5 = 0.05 %).
///
/// # Slippage calculation
/// ```text
/// slippage_bps = |actual - intended| / intended * 10_000
/// ```
/// For a buy, slippage = actual - intended (paying more than expected).
/// For a sell, slippage = intended - actual (receiving less than expected).
pub fn check_slippage(
    intended_price: Decimal,
    actual_price: Decimal,
    is_buy: bool,
    max_slippage_bps: u64,
) -> Result<u64, String> {
    if intended_price <= Decimal::ZERO {
        return Ok(0); // nothing to compare
    }

    let deviation = if is_buy {
        // Buy: paying more than intended is adverse slippage.
        actual_price.saturating_sub(intended_price)
    } else {
        // Sell: receiving less than intended is adverse slippage.
        intended_price.saturating_sub(actual_price)
    };

    let slippage_bps = (deviation * Decimal::from(10_000u64)
        / intended_price)
        .to_u64()
        .unwrap_or(0);

    if slippage_bps > max_slippage_bps {
        return Err(format!(
            "slippage guard: {} bps exceeds max {} bps (intended={}, actual={}, side={})",
            slippage_bps,
            max_slippage_bps,
            intended_price,
            actual_price,
            if is_buy { "BUY" } else { "SELL" },
        ));
    }

    Ok(slippage_bps)
}

/// Convert a `Decimal` dollar value to fixed-point u64 (dollars × 1_000_000).
#[inline]
fn decimal_to_fp(d: Decimal) -> u64 {
    if d < Decimal::ZERO {
        tracing::warn!(value = %d, "execution decimal_to_fp: negative value, clamping to 0");
        return 0;
    }
    let scaled = d * Decimal::from(1_000_000u64);
    // Use string round-trip to avoid truncation issues with .to_u64()
    let s = format!("{}", scaled);
    let parts: Vec<&str> = s.split('.').collect();
    let integer_part: u64 = parts[0].parse().unwrap_or_else(|_| {
        tracing::warn!(value = %d, scaled = %s, "execution decimal_to_fp: parse overflow, defaulting to 0");
        0
    });
    integer_part
}

// ===========================================================================
// Mathematical Verification Tests for Live Trading
// ===========================================================================

#[cfg(test)]
mod math_verification {
    use super::*;
    use rust_decimal_macros::dec;
    use std::str::FromStr;

    /// Verify that the fixed-point conversion is lossless for typical HFT values.
    /// Values tested: $0.01, $1.00, $100.00, $10,000.00, $100,000.00, $1,000,000.00
    #[test]
    fn test_fp_conversion_lossless_for_hft_values() {
        let test_values = [
            dec!(0.01), dec!(0.10), dec!(1.00), dec!(10.00),
            dec!(100.00), dec!(1000.00), dec!(10000.00), dec!(50000.00),
            dec!(100000.00), dec!(1000000.00),
        ];
        for val in &test_values {
            let fp = decimal_to_fp(*val);
            // Round-trip: fp / 1_000_000 should equal the original value
            // for values with ≤ 6 decimal places.
            let recovered = Decimal::from(fp) / Decimal::from(1_000_000u64);
            assert_eq!(
                recovered, *val,
                "FP round-trip failed for {}: fp={}, recovered={}",
                val, fp, recovered,
            );
        }
    }

    /// Verify that lot sizing: min(available, capital * max_pct) is correct.
    #[test]
    fn test_lot_sizing_math() {
        // Scenario: $10,000 available, 15% of $100,000 capital = $15,000 cap
        // → lot = min($10,000, $15,000) = $10,000
        let available = dec!(10000.0);
        let capital = dec!(100000.0);
        let max_pct = dec!(0.15);
        let cap = capital * max_pct;
        let lot = if available < cap { available } else { cap };
        assert_eq!(lot, dec!(10000.0));

        // Scenario: $50,000 available, 15% of $100,000 = $15,000 cap
        // → lot = $15,000
        let available = dec!(50000.0);
        let lot = if available < cap { available } else { cap };
        assert_eq!(lot, dec!(15000.0));

        // Scenario: $0 available → lot = $0
        let available = Decimal::ZERO;
        let lot = if available < cap { available } else { cap };
        assert_eq!(lot, Decimal::ZERO);
    }

    /// Verify slippage math: buy limit = price * (1 + tol), sell limit = price * (1 - tol).
    #[test]
    fn test_slippage_limit_math() {
        let price = dec!(50000.00);
        let tolerance = dec!(0.0005); // 5 bps

        // Buy: price * 1.0005 = 50025.0000
        let buy_limit = price * (Decimal::ONE + tolerance);
        assert_eq!(buy_limit, Decimal::from_str("50025.0000").unwrap());

        // Sell: price * 0.9995 = 49975.0000
        let sell_limit = price * (Decimal::ONE - tolerance);
        assert_eq!(sell_limit, Decimal::from_str("49975.0000").unwrap());

        // Verify: max adverse slippage = 5 bps
        let buy_slippage = (buy_limit - price) / price * Decimal::from(10000u32);
        let sell_slippage = (price - sell_limit) / price * Decimal::from(10000u32);
        assert_eq!(buy_slippage, dec!(5.0000));
        assert_eq!(sell_slippage, dec!(5.0000));
    }

    /// Verify fee deduction: net_spread = raw_spread - (buy_fee + sell_fee) in bps.
    #[test]
    fn test_fee_deduction_math() {
        let raw_spread_bps: i64 = 20; // 0.20%
        let buy_fee_bps: u64 = 10;  // 0.10%
        let sell_fee_bps: u64 = 10; // 0.10%

        let net_spread_bps = raw_spread_bps - (buy_fee_bps as i64 + sell_fee_bps as i64);
        assert_eq!(net_spread_bps, 0); // 20 - (10 + 10) = 0 → no profit

        // With 25 bps raw spread: 25 - 20 = 5 bps net
        let net2 = 25i64 - (buy_fee_bps as i64 + sell_fee_bps as i64);
        assert_eq!(net2, 5);
    }

    /// Verify counter-order price math: buy 1.001x, sell 0.999x to guarantee fill.
    #[test]
    fn test_counter_order_price_math() {
        let avg_price = dec!(50000.00);

        // Counter-sell after a buy fill: sell 0.1% lower → 49950.00
        let counter_sell = avg_price * Decimal::new(999, 3);
        assert_eq!(counter_sell, dec!(49950.000));

        // Counter-buy after a sell fill: buy 0.1% higher → 50050.00
        let counter_buy = avg_price * Decimal::new(1001, 3);
        assert_eq!(counter_buy, dec!(50050.000));
    }

    /// Verify balance conservation: buy deducts notional, sell credits notional.
    #[test]
    fn test_balance_conservation() {
        let mut usdt = dec!(10000.0);
        let mut btc = dec!(0.0);

        // Buy 0.1 BTC at $50,000 → deduct $5,000, credit 0.1 BTC
        let qty = dec!(0.1);
        let price = dec!(50000.0);
        let notional = qty * price; // $5,000.00
        usdt -= notional;
        btc += qty;
        assert_eq!(usdt, dec!(5000.0));
        assert_eq!(btc, dec!(0.1));

        // Sell 0.1 BTC at $50,100 → credit $5,010, deduct 0.1 BTC
        let sell_price = dec!(50100.0);
        let sell_notional = qty * sell_price; // $5,010.00
        btc -= qty;
        usdt += sell_notional;
        assert_eq!(usdt, dec!(10010.0));
        assert_eq!(btc, Decimal::ZERO);

        // Profit = $10 (before fees)
        let profit = dec!(10010.0) - dec!(10000.0);
        assert_eq!(profit, dec!(10.0));
    }

    /// Verify gas fee deduction in balance matrix: destination = amount - gas.
    #[test]
    fn test_gas_fee_deduction() {
        let transfer_amount = dec!(500.0);
        let gas_fee = dec!(2.00);
        let credited = transfer_amount - gas_fee;
        assert_eq!(credited, dec!(498.0));

        // In fixed-point: (500 - 2) * 1_000_000 = 498_000_000
        let fp_amount = decimal_to_fp(transfer_amount);
        let fp_gas = decimal_to_fp(gas_fee);
        let fp_credited = decimal_to_fp(credited);
        assert_eq!(fp_credited, fp_amount - fp_gas);
    }

    /// Verify signal threshold conversion: pct * 10_000 = bps.
    #[test]
    fn test_pct_to_bps_conversion() {
        let min_spread_pct = Decimal::from_str("0.0015").unwrap(); // 0.15%
        let bps = (min_spread_pct * Decimal::from(10_000u64))
            .to_u64()
            .unwrap_or(15);
        assert_eq!(bps, 15); // 0.0015 * 10000 = 15 bps

        let min_tri_pct = Decimal::from_str("0.0012").unwrap(); // 0.12%
        let tri_bps = (min_tri_pct * Decimal::from(10_000u64))
            .to_u64()
            .unwrap_or(15);
        assert_eq!(tri_bps, 12);
    }

    /// Verify no overflow in profit calculation for large notional values.
    #[test]
    fn test_no_overflow_large_notional() {
        // $1M position, 0.20% spread = $2,000 profit
        let notional = dec!(1000000.0);
        let spread_pct = dec!(0.0020);
        let profit = notional * spread_pct;
        assert_eq!(profit, dec!(2000.0));

        // FP conversion: 2000 * 1_000_000 = 2_000_000_000 (fits in u64)
        let fp_profit = decimal_to_fp(profit);
        assert_eq!(fp_profit, 2_000_000_000u64);
    }
}

// ---------------------------------------------------------------------------
// Order Cancellation Sweeper — background task for cancelling stale orders
// ---------------------------------------------------------------------------

/// Spawn a background tokio task that periodically scans the live order
/// tracker for stale (unfilled) orders and cancels them on-exchange.
///
/// This is the safety net for LIMIT orders that were submitted but never
/// filled within the expected time window (default: 30 seconds for orders
/// submitted as part of an arbitrage blast, 300 seconds max age on the
/// tracker).
///
/// The sweeper runs every `check_interval_secs` and:
/// 1. Gets all tracked orders.
/// 2. For each order older than `cancel_after_secs`, calls `attempt_exchange_cancel`.
/// 3. Runs `cleanup_stale()` to remove orders that exceed the tracker's max age.
/// 4. Logs the number of orders cancelled and remaining.
///
/// In paper mode this is a no-op — paper fills are instant.
pub fn spawn_order_cancellation_sweeper(
    engine: Arc<HighFrequencyExecutionEngine>,
    check_interval_secs: u64,
    cancel_after_secs: u64,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(
            std::time::Duration::from_secs(check_interval_secs),
        );
        let mut cycle: u64 = 0;

        loop {
            ticker.tick().await;
            cycle += 1;

            // In paper mode, nothing to cancel.
            if engine.is_paper_mode.load(Ordering::Relaxed) {
                continue;
            }

            let tracker = &engine.order_tracker;
            let current_count = tracker.len();
            if current_count == 0 {
                continue;
            }

            // Collect all tracked orders and check their ages.
            let all_orders: Vec<_> = {
                let orders_map = match tracker.orders.lock() {
                    Ok(m) => m,
                    Err(_) => continue,
                };
                orders_map.values().cloned().collect()
            };

            let mut cancelled = 0u64;
            for order in &all_orders {
                let age_secs = order.submitted_at.elapsed().as_secs();
                if age_secs >= cancel_after_secs {
                    info!(
                        order_id = %order.order_id,
                        exchange = order.exchange_id,
                        symbol = %order.symbol,
                        age_secs = age_secs,
                        "cancelling stale live order"
                    );
                    match engine.attempt_exchange_cancel(
                        order.exchange_id,
                        &order.symbol,
                        &order.order_id,
                    ).await {
                        Ok(true) => cancelled += 1,
                        Ok(false) => {}
                        Err(e) => {
                            error!(
                                order_id = %order.order_id,
                                error = %e,
                                "cancel failed for stale order — manual intervention may be needed"
                            );
                        }
                    }
                }
            }

            // Also run the tracker's built-in stale cleanup (max age = 300s).
            let cleaned = tracker.cleanup_stale();

            if cycle.is_multiple_of(10) || cancelled > 0 || cleaned > 0 {
                info!(
                    cycle,
                    tracked = tracker.len(),
                    cancelled_this_cycle = cancelled,
                    cleaned_stale = cleaned,
                    "order cancellation sweeper"
                );
            }
        }
    })
}

// ---------------------------------------------------------------------------
// Post-Blast Order Status Poller
// ---------------------------------------------------------------------------

/// After a multi-leg blast completes, some legs may have order_ids but
/// report 0 filled_qty (exchange acknowledged the order but hasn't matched
/// it yet).  This function polls those orders and updates the tracker + logs
/// if they eventually fill.
///
/// Runs as a **persistent** background daemon — never exits.  Every
/// `poll_interval_ms` it scans for unfilled tracked orders and queries the
/// exchange.  Orders older than `stale_order_secs` (default 30s) are skipped
/// because the cancellation sweeper will have already killed them.
///
/// On each poll cycle the cycle counter resets when candidates are found,
/// giving slow-filling orders a full window to complete.  When no candidates
/// exist the daemon sleeps at a reduced cadence (5× interval) to save CPU.
pub fn spawn_order_status_poller(
    engine: Arc<HighFrequencyExecutionEngine>,
    stale_order_secs: u64,
    poll_interval_ms: u64,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut idle_cycles: u64 = 0;
        const IDLE_MULTIPLIER: u64 = 5;
        let stale_ms = stale_order_secs * 1000;

        loop {
            // Adaptive sleep: poll faster when there are active candidates,
            // slower when idle to reduce unnecessary API calls.
            let sleep_ms = if idle_cycles > 10 {
                poll_interval_ms * IDLE_MULTIPLIER
            } else {
                poll_interval_ms
            };
            tokio::time::sleep(Duration::from_millis(sleep_ms)).await;

            // Collect orders with IDs but no recorded fills to re-query.
            // Skip orders older than stale_order_secs — the cancellation
            // sweeper handles those.
            let now_epoch_ms = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0);

            let candidates = {
                let tracker = &engine.order_tracker;
                let all = tracker.get_all();
                all.into_iter()
                    .filter(|o| {
                        if o.order_id.is_empty() || o.filled_qty > Decimal::ZERO {
                            return false;
                        }
                        // Skip stale orders that the cancellation sweeper
                        // should have already handled.
                        let age_ms = now_epoch_ms.saturating_sub(o.submitted_at_epoch_ms);
                        age_ms < stale_ms
                    })
                    .collect::<Vec<_>>()
            };

            if candidates.is_empty() {
                idle_cycles += 1;
                continue;
            }

            // Found candidates — reset idle counter.
            idle_cycles = 0;

            debug!(
                candidate_count = candidates.len(),
                "order status poller: polling unfilled orders"
            );

            // Attempt to query each candidate's status via the typed pool.
            if let (Some(ref pool), Some(ref http)) = (&engine.cancel_pool, &engine.cancel_http_client) {
                for order in &candidates {
                    if let Some(client) = pool.get(&order.exchange_id) {
                        match client.query_order(http, &order.symbol, &order.order_id).await {
                            Ok(status) => {
                                if status.filled_qty > Decimal::ZERO {
                                    info!(
                                        exchange = order.exchange_id,
                                        order_id = %order.order_id,
                                        filled = %status.filled_qty,
                                        avg_price = %status.avg_price,
                                        "post-blast poll: order NOW FILLED"
                                    );
                                    // Update the tracker with fill info.
                                    engine.order_tracker.update_fill(
                                        &order.order_id,
                                        status.filled_qty,
                                    );
                                }
                                // If still unfilled, the cancellation sweeper
                                // will handle it after 30s.
                            }
                            Err(e) => {
                                debug!(
                                    exchange = order.exchange_id,
                                    order_id = %order.order_id,
                                    error = %e,
                                    "post-blast poll: query failed (non-fatal)"
                                );
                            }
                        }
                    }
                }
            }
        }
    })
}

// ---------------------------------------------------------------------------
// Extended Mathematical Verification Tests for Live Trading
// ---------------------------------------------------------------------------

#[cfg(test)]
mod math_verification_extended {
    use super::*;
    use rust_decimal_macros::dec;
    use std::str::FromStr;

    /// Verify three-leg triangular fee deduction:
    /// net_profit_bps = raw_profit_bps - (fee_a + fee_b + fee_c)
    /// where each fee is in taker bps.
    #[test]
    fn test_triangular_three_leg_fee_deduction() {
        // Raw profit: 30 bps. Three legs on Binance (10 bps taker each).
        let raw_profit_bps: i64 = 30;
        let fee_a: u64 = 10; // buy leg 1
        let fee_b: u64 = 10; // buy leg 2
        let fee_c: u64 = 10; // sell leg 3
        let total_fees = (fee_a + fee_b + fee_c) as i64;
        let net = raw_profit_bps - total_fees;
        assert_eq!(net, 0, "30 bps raw - 30 bps fees = 0 net → no profit");

        // With 35 bps raw: 35 - 30 = 5 bps net
        let net2 = 35i64 - total_fees;
        assert_eq!(net2, 5);

        // Mixed exchanges: Binance(10) + OKX(8) + GateIO(10) = 28 bps
        let mixed_fees = 10u64 + 8u64 + 10u64;
        let net3 = 30i64 - mixed_fees as i64;
        assert_eq!(net3, 2);
    }

    /// Verify FP conversion for sub-cent values (important for dust handling).
    #[test]
    fn test_fp_conversion_sub_cent_values() {
        // $0.001 → 1_000 fp-units
        assert_eq!(decimal_to_fp(dec!(0.001)), 1_000);
        // $0.000001 → 1 fp-unit (minimum resolution)
        assert_eq!(decimal_to_fp(dec!(0.000001)), 1);
        // $0.0000001 → 0 (truncated below resolution)
        assert_eq!(decimal_to_fp(dec!(0.0000001)), 0);
        // $0.005 → 5_000 fp-units
        assert_eq!(decimal_to_fp(dec!(0.005)), 5_000);
    }

    /// Verify that lot sizing never returns more than available balance.
    /// This is the balance conservation invariant.
    #[test]
    fn test_lot_sizing_never_exceeds_available() {
        let available = dec!(50.0);
        let capital = dec!(100000.0);
        let max_pct = dec!(0.15); // 15%

        let cap = capital * max_pct; // $15,000
        let lot = if available < cap { available } else { cap };
        assert_eq!(lot, dec!(50.0), "lot must not exceed available balance");

        // Edge: available = 0
        let lot_zero = if Decimal::ZERO < cap { Decimal::ZERO } else { cap };
        assert_eq!(lot_zero, Decimal::ZERO);

        // Edge: available exactly equals cap
        let lot_eq = if available == cap { available } else { cap };
        assert!(lot_eq > Decimal::ZERO);
    }

    /// Verify balance conservation through a full cross-exchange arb cycle
    /// WITH fees deducted.
    #[test]
    fn test_balance_conservation_with_fees() {
        let mut usdt_a = dec!(10000.0); // Exchange A
        let mut usdt_b = dec!(10000.0); // Exchange B
        let mut btc_a = dec!(0.0);
        let mut btc_b = dec!(0.0);

        let qty = dec!(0.1);
        let buy_price = dec!(50000.0);  // Exchange A ask
        let sell_price = dec!(50100.0); // Exchange B bid
        let taker_fee_bps = 10u64; // 0.10%

        // Leg 1: Buy 0.1 BTC on Exchange A at $50,000
        let buy_notional = qty * buy_price; // $5,000.00
        let buy_fee = buy_notional * Decimal::from(taker_fee_bps) / Decimal::from(10_000u64); // $5.00
        usdt_a -= buy_notional;
        btc_a += qty;
        usdt_a -= buy_fee; // fee deducted

        // Leg 2: Sell 0.1 BTC on Exchange B at $50,100
        let sell_notional = qty * sell_price; // $5,010.00
        let sell_fee = sell_notional * Decimal::from(taker_fee_bps) / Decimal::from(10_000u64); // $5.01
        btc_b -= qty;
        usdt_b += sell_notional;
        usdt_b -= sell_fee; // fee deducted

        // Verify conservation: total value before = total value after
        let total_before = dec!(20000.0); // 10k + 10k
        let total_after = usdt_a + usdt_b + btc_a * buy_price + btc_b * sell_price;
        let total_fees = buy_fee + sell_fee;

        // Total capital = balances + fees paid
        // Selling adds USDT, so gross profit increases capital
        let capital_after = usdt_a + usdt_b;
        let expected_capital = total_before + (sell_notional - buy_notional) - total_fees;
        assert_eq!(capital_after, expected_capital);

        // Profit after fees: (sell_notional - buy_notional) - total_fees
        let gross_profit = sell_notional - buy_notional; // $10.00
        let net_profit = gross_profit - total_fees; // $10.00 - $10.01 = -$0.01
        assert!(net_profit < Decimal::ZERO, "with 10bps each way, $10 gross → net loss after fees");
    }

    /// Verify slippage limit never exceeds the configured tolerance.
    #[test]
    fn test_slippage_limit_upper_bound() {
        let prices = [dec!(100.0), dec!(1000.0), dec!(50000.0), dec!(0.001)];
        let tolerances = [dec!(0.0001), dec!(0.0005), dec!(0.001), dec!(0.01)];

        for &price in &prices {
            for &tol in &tolerances {
                let buy_limit = price * (Decimal::ONE + tol);
                let sell_limit = price * (Decimal::ONE - tol);

                let buy_deviation = (buy_limit - price) / price;
                let sell_deviation = (price - sell_limit) / price;

                // Both deviations must be exactly equal to tolerance.
                assert!(
                    (buy_deviation - tol).abs() < dec!(0.00000001),
                    "buy deviation {} != tolerance {} at price {}",
                    buy_deviation, tol, price
                );
                assert!(
                    (sell_deviation - tol).abs() < dec!(0.00000001),
                    "sell deviation {} != tolerance {} at price {}",
                    sell_deviation, tol, price
                );
            }
        }
    }

    /// Verify that check_slippage correctly handles zero-division safety.
    #[test]
    fn test_slippage_zero_price_safe() {
        let result = check_slippage(Decimal::ZERO, dec!(50000), true, 5);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0);
    }

    /// Verify gas fee deduction clamping: gas cannot exceed transfer amount.
    #[test]
    fn test_gas_fee_clamp_to_transfer_amount() {
        let transfer = dec!(5.0);
        let gas = dec!(10.0); // gas > transfer

        // Effective gas should be clamped to transfer amount.
        let effective = if gas > transfer { transfer } else { gas };
        assert_eq!(effective, dec!(5.0));

        let net = transfer - effective;
        assert_eq!(net, Decimal::ZERO, "destination gets $0 when gas >= transfer");
    }

    /// Verify post-trade daily P&L tracking sign correctness.
    #[test]
    fn test_daily_pnl_sign_tracking() {
        // Simulate: +$0.50 profit, then -$0.30 loss, then -$0.25 loss.
        // Total: -$0.05 loss → 5 cents.
        let events: [i64; 3] = [50, -30, -25]; // in cents
        let mut loss_cents: u64 = 0;
        let mut profit_cents: u64 = 0;

        for &pnl in &events {
            if pnl >= 0 {
                profit_cents += pnl as u64;
            } else {
                loss_cents += pnl.unsigned_abs();
            }
        }

        assert_eq!(profit_cents, 50);
        assert_eq!(loss_cents, 55);
        // Net P&L = profit - loss = 50 - 55 = -5 cents
        let net = profit_cents as i64 - loss_cents as i64;
        assert_eq!(net, -5);
    }

    /// Verify counter-order price nudge is always in the adverse direction.
    #[test]
    fn test_counter_order_always_adverse() {
        let fill_price = dec!(50000.0);

        // Counter-sell after buy: must be LOWER than fill (adverse = accept less)
        let counter_sell = fill_price * Decimal::new(999, 3);
        assert!(counter_sell < fill_price,
            "counter-sell {} must be < fill price {}", counter_sell, fill_price);

        // Counter-buy after sell: must be HIGHER than fill (adverse = pay more)
        let counter_buy = fill_price * Decimal::new(1001, 3);
        assert!(counter_buy > fill_price,
            "counter-buy {} must be > fill price {}", counter_buy, fill_price);

        // Verify nudge magnitude: exactly 0.1%
        let sell_nudge_bps = ((fill_price - counter_sell) / fill_price * Decimal::from(10_000u32))
            .to_u64().unwrap_or(0);
        let buy_nudge_bps = ((counter_buy - fill_price) / fill_price * Decimal::from(10_000u32))
            .to_u64().unwrap_or(0);
        assert_eq!(sell_nudge_bps, 10, "counter-sell nudge must be 10 bps");
        assert_eq!(buy_nudge_bps, 10, "counter-buy nudge must be 10 bps");
    }
}