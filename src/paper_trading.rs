use chrono::Utc;
use rust_decimal::Decimal;
use rust_decimal_macros::dec;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

// ---------------------------------------------------------------------------
// Slippage helper (LCG, 1–5 bps)
// ---------------------------------------------------------------------------

/// Global LCG state for pseudo-random slippage sampling.
/// Thread-safe via `AtomicU64`.
/// H-6 fix: Seed from SystemTime instead of hardcoded 42.
static LCG_STATE: AtomicU64 = AtomicU64::new(0);

/// Whether the LCG has been initialised.
static LCG_INITIALISED: AtomicU64 = AtomicU64::new(0);

/// LCG parameters (Numerical Recipes classic).
const LCG_A: u64 = 1_664_525;
const LCG_C: u64 = 1_013_904_223;
const LCG_M: u64 = 1 << 32;

/// Minimum partial-fill amount in basis points (50 %).
const PARTIAL_FILL_MIN_BPS: u64 = 5000;

/// Advance the global LCG and return the raw 32-bit value.
/// Safe to call from multiple threads.
fn lcg_next() -> u32 {
    // Lazy-init seed from system time on first call.
    if LCG_INITIALISED.load(Ordering::Relaxed) == 0 {
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(42);
        LCG_STATE.store(seed, Ordering::Relaxed);
        LCG_INITIALISED.store(1, Ordering::Relaxed);
    }
    LCG_STATE
        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |s| {
            Some((LCG_A.wrapping_mul(s).wrapping_add(LCG_C)) % LCG_M)
        })
        .unwrap_or(1) as u32
}

/// Returns a pseudo-random slippage in the range **1–5 basis points** using a
/// simple Linear Congruential Generator.  Safe to call from multiple threads.
fn random_slippage_bps() -> u64 {
    1 + (lcg_next() % 5) as u64
}

/// Fixed 3 bps slippage – provided for deterministic unit tests if desired.
#[cfg(test)]
#[allow(dead_code)]
fn fixed_slippage_bps() -> u64 {
    3
}

/// Maximum single-order notional in USD. Matches what a real exchange
/// would enforce to prevent accidental catastrophic orders.
const MAX_ORDER_NOTIONAL_USD: Decimal = dec!(100_000);

// ---------------------------------------------------------------------------
// PaperTradeRecord
// ---------------------------------------------------------------------------

/// A single recorded paper trade.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaperTradeRecord {
    pub timestamp: i64,
    pub exchange_id: u16,
    pub token_id: u16,
    pub symbol: String,
    pub side: String, // "BUY" or "SELL"
    pub qty: Decimal,
    pub price: Decimal,
    pub total: Decimal,
    pub simulated_slippage_bps: u64,
}

// ---------------------------------------------------------------------------
// PaperTradingPipeline
// ---------------------------------------------------------------------------

/// Virtual-portfolio simulator used for paper-trading HFT arbitrage strategies.
///
/// Token `0` is treated as the quote / settlement currency (USDT).  All
/// balances are stored as `Decimal` values.
pub struct PaperTradingPipeline {
    /// Per-token balances (`token_id -> balance`).
    pub balances: Arc<RwLock<HashMap<u16, Decimal>>>,
    /// Capital the pipeline was initialised with (USDT at token 0).
    pub initial_capital: Decimal,
    /// Running count of successfully filled trades.
    pub total_trades: AtomicU64,
    /// Realised PnL in fixed-point **cents** (hundredths of a dollar).
    pub total_pnl: AtomicI64,
    /// Chronological list of every filled `PaperTradeRecord`.
    pub trade_history: Arc<RwLock<Vec<PaperTradeRecord>>>,
    /// Fill probability (0–100 %). Default 95.
    pub fill_probability: AtomicU64,
    /// Maximum partial-fill amount in basis points (0–10 000). Default 9500 = 95 %.
    pub partial_fill_max_pct: AtomicU64,
    /// Simulated round-trip exchange latency in microseconds. Default 500 µs.
    pub simulated_latency_us: AtomicU64,
}

impl PaperTradingPipeline {
    /// Create a new pipeline funded with `initial_capital` USDT (token 0).
    ///
    /// For testing triangular arbitrage, BTC (token 1) and ETH (token 2) are
    /// pre-funded with 1.0 and 10.0 units respectively.
    /// FX quote currencies (JPY, EUR, GBP) are pre-funded for FX tri arb.
    pub fn new(initial_capital: Decimal) -> Self {
        let mut balances = HashMap::new();
        balances.insert(0u16, initial_capital);
        balances.insert(1u16, dec!(1.0));   // BTC – for triangular arb
        balances.insert(2u16, dec!(10.0));  // ETH – for triangular arb

        // FX tri arb quote currencies — pre-funded for cross-currency loops.
        // These use high token IDs to avoid collision with crypto assets.
        // The coin finder starts at 100, so FX slots use 50–59.
        balances.insert(50u16, dec!(150000));  // JPY — ~$1,000 USD equivalent
        balances.insert(51u16, dec!(1000));    // EUR — ~$1,000 USD equivalent
        balances.insert(52u16, dec!(800));     // GBP — ~$1,000 USD equivalent
        balances.insert(53u16, dec!(1500));    // AUD — ~$1,000 USD equivalent
        balances.insert(54u16, dec!(1300));    // CAD — ~$1,000 USD equivalent

        Self {
            balances: Arc::new(RwLock::new(balances)),
            initial_capital,
            total_trades: AtomicU64::new(0),
            total_pnl: AtomicI64::new(0),
            trade_history: Arc::new(RwLock::new(Vec::new())),
            fill_probability: AtomicU64::new(95),
            partial_fill_max_pct: AtomicU64::new(9500),
            simulated_latency_us: AtomicU64::new(500),
        }
    }

    /// Set the fill probability (0–100 %).
    ///
    /// Before filling, a random number is drawn. If it exceeds this threshold
    /// the fill is **rejected** (simulating network errors, rate limits, or
    /// insufficient exchange liquidity).
    pub fn set_fill_probability(&self, pct: u64) {
        self.fill_probability.store(pct.min(100), Ordering::SeqCst);
    }

    /// Set the maximum partial-fill amount in **basis points** (0–10 000).
    ///
    /// When a fill is accepted, the actual filled quantity is randomly chosen
    /// in the range `[PARTIAL_FILL_MIN_BPS, partial_fill_max_pct)` divided by
    /// 10 000.  A value of 10 000 disables partial fills (100 % fill every time).
    pub fn set_partial_fill_max_pct(&self, bps: u64) {
        self.partial_fill_max_pct.store(bps.min(10_000), Ordering::SeqCst);
    }

    /// Set the simulated round-trip exchange latency in **microseconds**.
    ///
    /// Before processing a fill the pipeline sleeps for this duration, mimicking
    /// real-world network + matching-engine round-trip time.
    pub fn set_simulated_latency_us(&self, us: u64) {
        self.simulated_latency_us.store(us, Ordering::SeqCst);
    }

    /// Allocate capital for an FX triangular arbitrage loop.
    ///
    /// Given a route like `USDT -> EUR -> JPY -> USDT`, this ensures
    /// all intermediate currencies have sufficient balance by checking
    /// and optionally funding them from the USDT reserve.
    ///
    /// Returns `Ok(())` if the allocation succeeds, or an error string.
    pub async fn allocate_fx_tri_capital(
        &self,
        intermediate_tokens: &[u16],
        amount_per_leg_usdt: Decimal,
    ) -> Result<(), String> {
        let mut balances = self.balances.write().await;

        // For each intermediate currency, ensure it has at least amount_per_leg
        for &token_id in intermediate_tokens {
            let current = balances.get(&token_id).copied().unwrap_or(Decimal::ZERO);
            if current < amount_per_leg_usdt {
                let shortfall = amount_per_leg_usdt - current;
                let usdt = balances.get(&0u16).copied().unwrap_or(Decimal::ZERO);
                if usdt < shortfall {
                    return Err(format!(
                        "FX tri arb allocation failed: USDT reserve {} < shortfall {} for token {}",
                        usdt, shortfall, token_id
                    ));
                }
                if let Some(usdt_bal) = balances.get_mut(&0u16) {
                    *usdt_bal -= shortfall;
                }
                *balances.entry(token_id).or_insert(Decimal::ZERO) += shortfall;
            }
        }

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Core simulation
    // -----------------------------------------------------------------------

    /// Simulate filling an order at `price` with a small random slippage,
    /// optional latency, fill-probability gate, and partial-fill model.
    ///
    /// * **Latency** – sleeps for `simulated_latency_us` µs before processing.
    /// * **Fill-probability** – rejects the fill outright with probability
    ///   `(100 - fill_probability)` % (simulating network errors / rate limits).
    /// * **Partial fill** – when accepted, the filled quantity is randomly
    ///   chosen in `[50 %, partial_fill_max_pct)` of the requested quantity.
    /// * **BUY**  – deducts `total` (actual_qty × effective_price) from USDT
    ///   and credits `actual_qty` to `token_id`.
    /// * **SELL** – deducts `actual_qty` from `token_id` and credits `total`
    ///   to USDT.
    ///
    /// If the source balance is insufficient (or the fill was rejected) a
    /// zeroed-out record is returned (no balances are mutated, no counters
    /// are incremented).
    pub async fn simulate_fill(
        &self,
        exchange_id: u16,
        token_id: u16,
        symbol: &str,
        qty: Decimal,
        price: Decimal,
        is_buy: bool,
    ) -> PaperTradeRecord {
        let side = if is_buy { "BUY" } else { "SELL" };
        let ts = Utc::now().timestamp_millis();

        // --- 1. Simulated latency ---
        let latency = self.simulated_latency_us.load(Ordering::SeqCst);
        if latency > 0 {
            tokio::time::sleep(Duration::from_micros(latency)).await;
        }

        // --- 2. Fill-probability gate ---
        let fill_pct = self.fill_probability.load(Ordering::SeqCst);
        let rand_val = lcg_next() as u64;
        if rand_val % 100 >= fill_pct {
            return PaperTradeRecord {
                timestamp: ts,
                exchange_id,
                token_id,
                symbol: symbol.to_string(),
                side: side.to_string(),
                qty: Decimal::ZERO,
                price: Decimal::ZERO,
                total: Decimal::ZERO,
                simulated_slippage_bps: 0,
            };
        }

        // --- 3. Partial fill ---
        // A value of 10 000 bps disables partial fills (100 % every time).
        let actual_qty = {
            let partial_max = self.partial_fill_max_pct.load(Ordering::SeqCst);
            if partial_max >= 10_000 {
                qty
            } else if partial_max <= PARTIAL_FILL_MIN_BPS {
                qty * Decimal::from(partial_max) / dec!(10000)
            } else {
                let range = partial_max - PARTIAL_FILL_MIN_BPS + 1; // inclusive upper bound
                let fill_bps = PARTIAL_FILL_MIN_BPS + (lcg_next() as u64 % range);
                qty * Decimal::from(fill_bps) / dec!(10000)
            }
        };

        // --- 4. Slippage ---
        let slippage_bps = random_slippage_bps();
        let slippage = Decimal::from(slippage_bps) / dec!(10000);

        let effective_price = if is_buy {
            price * (Decimal::ONE + slippage)
        } else {
            price * (Decimal::ONE - slippage)
        };

        let total = actual_qty * effective_price;

        // M-6: Enforce maximum order notional (same as live exchange limits).
        if total > MAX_ORDER_NOTIONAL_USD {
            return PaperTradeRecord {
                timestamp: ts,
                exchange_id,
                token_id,
                symbol: symbol.to_string(),
                side: side.to_string(),
                qty: Decimal::ZERO,
                price: Decimal::ZERO,
                total: Decimal::ZERO,
                simulated_slippage_bps: 0,
            };
        }

        // --- 5. Balance check & mutation ---
        let mut balances = self.balances.write().await;

        let ok = if is_buy {
            let usdt = balances.get(&0u16).copied().unwrap_or(Decimal::ZERO);
            if usdt < total {
                false
            } else {
                *balances.entry(0u16).or_insert(Decimal::ZERO) -= total;
                *balances.entry(token_id).or_insert(Decimal::ZERO) += actual_qty;
                true
            }
        } else {
            let tok_bal = balances.get(&token_id).copied().unwrap_or(Decimal::ZERO);
            if tok_bal < actual_qty {
                false
            } else {
                *balances.entry(token_id).or_insert(Decimal::ZERO) -= actual_qty;
                *balances.entry(0u16).or_insert(Decimal::ZERO) += total;
                true
            }
        };

        if !ok {
            // Insufficient balance – return zeroed record, do NOT increment
            // counters or push to history.
            return PaperTradeRecord {
                timestamp: ts,
                exchange_id,
                token_id,
                symbol: symbol.to_string(),
                side: side.to_string(),
                qty: Decimal::ZERO,
                price: Decimal::ZERO,
                total: Decimal::ZERO,
                simulated_slippage_bps: 0,
            };
        }

        // --- trade succeeded ---
        drop(balances); // release write lock before acquiring history lock

        self.total_trades.fetch_add(1, Ordering::SeqCst);

        // Update the cached PnL in fixed-point cents.
        {
            let bals = self.balances.read().await;
            let usdt = bals.get(&0u16).copied().unwrap_or(Decimal::ZERO);
            let pnl_decimal = usdt - self.initial_capital;
            let pnl_cents = decimal_to_cents(pnl_decimal);
            self.total_pnl.store(pnl_cents, Ordering::SeqCst);
        }

        let record = PaperTradeRecord {
            timestamp: ts,
            exchange_id,
            token_id,
            symbol: symbol.to_string(),
            side: side.to_string(),
            qty: actual_qty,
            price: effective_price,
            total,
            simulated_slippage_bps: slippage_bps,
        };

        {
            let mut history = self.trade_history.write().await;
            history.push(record.clone());
        }

        record
    }

    // -----------------------------------------------------------------------
    // Read-only accessors
    // -----------------------------------------------------------------------

    /// Return the current balance for a single token.
    pub async fn get_balance(&self, token_id: u16) -> Decimal {
        let balances = self.balances.read().await;
        balances.get(&token_id).copied().unwrap_or(Decimal::ZERO)
    }

    /// Return a clone of the entire balance map.
    pub async fn get_all_balances(&self) -> HashMap<u16, Decimal> {
        let balances = self.balances.read().await;
        balances.clone()
    }

    /// Return the number of successfully filled trades.
    pub async fn get_total_trades(&self) -> u64 {
        self.total_trades.load(Ordering::SeqCst)
    }

    /// Compute current PnL as `USDT_balance - initial_capital`.
    ///
    /// This is a **realised** PnL measure in USDT terms: any tokens still held
    /// are not priced because no external price oracle is available inside
    /// this module.
    pub async fn get_total_pnl(&self) -> Decimal {
        let balances = self.balances.read().await;
        let usdt = balances.get(&0u16).copied().unwrap_or(Decimal::ZERO);
        usdt - self.initial_capital
    }

    /// Return a clone of the full trade history.
    pub async fn get_trade_history(&self) -> Vec<PaperTradeRecord> {
        let history = self.trade_history.read().await;
        history.clone()
    }

    // -----------------------------------------------------------------------
    // Maintenance
    // -----------------------------------------------------------------------

    /// Reset all state back to the initial configuration:
    /// * balances → USDT = initial_capital, BTC = 1.0, ETH = 10.0,
    ///   plus FX currencies for tri arb.
    /// * counters and history are cleared.
    pub async fn reset(&self) {
        let mut balances = self.balances.write().await;
        balances.clear();
        balances.insert(0u16, self.initial_capital);
        balances.insert(1u16, dec!(1.0));
        balances.insert(2u16, dec!(10.0));
        // FX tri arb quote currencies
        balances.insert(50u16, dec!(150000));  // JPY
        balances.insert(51u16, dec!(1000));    // EUR
        balances.insert(52u16, dec!(800));     // GBP
        balances.insert(53u16, dec!(1500));    // AUD
        balances.insert(54u16, dec!(1300));    // CAD

        self.total_trades.store(0, Ordering::SeqCst);
        self.total_pnl.store(0, Ordering::SeqCst);

        let mut history = self.trade_history.write().await;
        history.clear();
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Convert a `Decimal` (dollar value) to fixed-point **cents** stored as `i64`.
///
/// Uses rounding to nearest cent.  The string-round-trip avoids lossy `f64`
/// conversion for large decimal values.
fn decimal_to_cents(value: Decimal) -> i64 {
    let cents = (value * Decimal::from(100u32)).round();
    match cents.to_string().parse::<i64>() {
        Ok(v) => v,
        Err(_) => {
            tracing::warn!(%value, "PnL overflow in decimal_to_cents, clamping");
            if value > Decimal::ZERO { i64::MAX } else { i64::MIN }
        }
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use rust_decimal_macros::dec;

    /// Helper: build a pipeline with a known USDT capital.
    /// Disables latency, rejection, and partial fills so tests are deterministic.
    fn make_pipeline(usdt_capital: &str) -> PaperTradingPipeline {
        let cap: Decimal = usdt_capital.parse().unwrap();
        let p = PaperTradingPipeline::new(cap);
        p.set_fill_probability(100);
        p.set_partial_fill_max_pct(10_000); // 100 % — no partial fills
        p.set_simulated_latency_us(0);      // no latency
        p
    }

    #[tokio::test]
    async fn test_initial_balance_set() {
        let pipeline = make_pipeline("10000");

        let usdt = pipeline.get_balance(0).await;
        assert_eq!(usdt, dec!(10000));

        let btc = pipeline.get_balance(1).await;
        assert_eq!(btc, dec!(1.0));

        let eth = pipeline.get_balance(2).await;
        assert_eq!(eth, dec!(10.0));
    }

    #[tokio::test]
    async fn test_buy_deducts_usdt() {
        let pipeline = make_pipeline("10000");
        let usdt_before = pipeline.get_balance(0).await;
        let btc_before = pipeline.get_balance(1).await;

        // Buy 0.1 BTC at $50 000
        let record = pipeline
            .simulate_fill(1, 1, "BTC/USDT", dec!(0.1), dec!(50000), true)
            .await;

        assert_eq!(record.side, "BUY");
        assert_eq!(record.qty, dec!(0.1));
        assert!(record.total > Decimal::ZERO);

        let usdt_after = pipeline.get_balance(0).await;
        let btc_after = pipeline.get_balance(1).await;

        // USDT should have decreased by exactly `record.total`
        assert_eq!(usdt_before - usdt_after, record.total);
        // BTC should have increased by exactly the bought quantity
        assert_eq!(btc_after - btc_before, dec!(0.1));
    }

    #[tokio::test]
    async fn test_sell_adds_usdt() {
        let pipeline = make_pipeline("10000");

        let usdt_before = pipeline.get_balance(0).await;
        let btc_before = pipeline.get_balance(1).await;

        // Sell 0.5 of the pre-funded BTC (token 1) at $51 000
        let record = pipeline
            .simulate_fill(2, 1, "BTC/USDT", dec!(0.5), dec!(51000), false)
            .await;

        assert_eq!(record.side, "SELL");
        assert_eq!(record.qty, dec!(0.5));
        assert!(record.total > Decimal::ZERO);

        let usdt_after = pipeline.get_balance(0).await;
        let btc_after = pipeline.get_balance(1).await;

        // USDT should have increased by exactly `record.total`
        assert_eq!(usdt_after - usdt_before, record.total);
        // BTC should have decreased by exactly the sold quantity
        assert_eq!(btc_before - btc_after, dec!(0.5));
    }

    #[tokio::test]
    async fn test_insufficient_balance_rejected() {
        let pipeline = make_pipeline("100"); // only $100 USDT

        // Try to buy 1 BTC at $50 000 – far exceeds $100
        let record = pipeline
            .simulate_fill(1, 1, "BTC/USDT", dec!(1.0), dec!(50000), true)
            .await;

        // The trade must be rejected – all value fields zeroed
        assert_eq!(record.qty, Decimal::ZERO);
        assert_eq!(record.price, Decimal::ZERO);
        assert_eq!(record.total, Decimal::ZERO);
        assert_eq!(record.simulated_slippage_bps, 0);

        // Balances must be completely unchanged
        assert_eq!(pipeline.get_balance(0).await, dec!(100));
        assert_eq!(pipeline.get_balance(1).await, dec!(1.0)); // pre-funded, untouched

        // Trade counter must not have incremented
        assert_eq!(pipeline.get_total_trades().await, 0);
    }

    #[tokio::test]
    async fn test_trade_history_records() {
        let pipeline = make_pipeline("100000");

        // Execute two trades
        pipeline
            .simulate_fill(1, 1, "BTC/USDT", dec!(0.5), dec!(50000), true)
            .await;
        pipeline
            .simulate_fill(2, 2, "ETH/USDT", dec!(5.0), dec!(3000), false)
            .await;

        let history = pipeline.get_trade_history().await;
        assert_eq!(history.len(), 2);

        // First record – the BUY
        assert_eq!(history[0].side, "BUY");
        assert_eq!(history[0].symbol, "BTC/USDT");
        assert_eq!(history[0].exchange_id, 1);
        assert_eq!(history[0].token_id, 1);

        // Second record – the SELL
        assert_eq!(history[1].side, "SELL");
        assert_eq!(history[1].symbol, "ETH/USDT");
        assert_eq!(history[1].exchange_id, 2);
        assert_eq!(history[1].token_id, 2);

        // Total trade counter reflects both fills
        assert_eq!(pipeline.get_total_trades().await, 2);

        // Timestamps must be non-zero (millis since epoch)
        assert!(history[0].timestamp > 0);
        assert!(history[1].timestamp > 0);
    }
}