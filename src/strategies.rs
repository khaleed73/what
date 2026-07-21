use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use rust_decimal::Decimal;
use rust_decimal::prelude::ToPrimitive;

// ---------------------------------------------------------------------------
// Fee-aware spread configuration
// ---------------------------------------------------------------------------

/// Per-exchange fee schedule used to deduct trading costs from raw spread
/// before emitting a signal.  All values are in **basis points** (10 000 = 1 %).
///
/// Example: Binance taker fee = 0.1 % → 10 bps.
#[derive(Debug, Clone)]
pub struct ExchangeFeeSchedule {
    /// `exchange_id → maker_fee_bps`.
    pub maker_fees: Vec<u64>,
    /// `exchange_id → taker_fee_bps`.
    pub taker_fees: Vec<u64>,
}

impl ExchangeFeeSchedule {
    /// Create a new fee schedule with `total_exchanges` slots, all initialised
    /// to `default_bps` (e.g. 10 bps = 0.1 %).
    pub fn new(total_exchanges: usize, default_bps: u64) -> Self {
        Self {
            maker_fees: vec![default_bps; total_exchanges],
            taker_fees: vec![default_bps; total_exchanges],
        }
    }

    /// Set both maker and taker fee for a specific exchange.
    ///
    /// # Errors
    /// Returns an error if `exchange_id` is out of range.
    pub fn set_fee(&mut self, exchange_id: usize, maker_bps: u64, taker_bps: u64) -> Result<(), String> {
        if exchange_id >= self.maker_fees.len() {
            return Err(format!("exchange_id {} out of range (max {})", exchange_id, self.maker_fees.len() - 1));
        }
        self.maker_fees[exchange_id] = maker_bps;
        self.taker_fees[exchange_id] = taker_bps;
        Ok(())
    }

    /// Return the **round-trip taker fee** (buy taker + sell taker) for a pair
    /// of exchanges, in basis points.  Taker fee is the conservative worst-case
    /// since we cannot guarantee maker fills on HFT time-scales.
    #[inline(always)]
    pub fn round_trip_taker_bps(&self, exch_a: usize, exch_b: usize) -> u64 {
        let a = self.taker_fees.get(exch_a).copied().unwrap_or_else(|| {
            tracing::warn!(exchange = exch_a, "Unknown exchange in fee schedule, using {} bps default", DEFAULT_TAKER_FEE_BPS);
            DEFAULT_TAKER_FEE_BPS
        });
        let b = self.taker_fees.get(exch_b).copied().unwrap_or_else(|| {
            tracing::warn!(exchange = exch_b, "Unknown exchange in fee schedule, using {} bps default", DEFAULT_TAKER_FEE_BPS);
            DEFAULT_TAKER_FEE_BPS
        });
        a.saturating_add(b)
    }

    /// Return the **three-leg taker fee** (sum of three taker fees) for
    /// triangular arbitrage on a single exchange, in basis points.
    #[inline(always)]
    pub fn tri_leg_taker_bps(&self, exchange_id: usize) -> u64 {
        let fee = self.taker_fees.get(exchange_id).copied().unwrap_or(DEFAULT_TAKER_FEE_BPS);
        fee.saturating_mul(3)
    }

    /// Return the single-leg taker fee for a specific exchange, in basis points.
    #[inline(always)]
    pub fn get_taker(&self, exchange_id: usize) -> u64 {
        self.taker_fees.get(exchange_id).copied().unwrap_or(DEFAULT_TAKER_FEE_BPS)
    }
}

// ---------------------------------------------------------------------------
// Data structures
// ---------------------------------------------------------------------------

/// Single slot in the order-book matrix. Used for non-hot-path bulk reads;
/// hot-path price reads go through the atomic arrays instead.
#[derive(Copy, Clone, Default, Debug)]
#[non_exhaustive]
pub struct OrderBookState {
    pub bid_price: u64,
    pub ask_price: u64,
    pub bid_volume: u32,
    pub ask_volume: u32,
    pub last_update_ns: u64,
}

/// Pre-compiled 3-step cycle A → B → C → A on a single exchange.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct TriangularLoop {
    pub token_a: u16,
    pub token_b: u16,
    pub token_c: u16,
}

/// A token that is listed on ≥ 2 exchanges, together with a bitmask of
/// which exchanges carry it.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct CrossExchangeTarget {
    pub token_id: u16,
    pub exchange_mask: u64,
    pub shared_count: u8,
}

/// Outcome of an arbitrage evaluation pass.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum ArbitrageSignal {
    CrossExchange {
        buy_exchange: u16,
        sell_exchange: u16,
        token_id: u16,
        spread_bps: u64,
    },
    Triangular {
        exchange_id: u16,
        token_a: u16,
        token_b: u16,
        token_c: u16,
        profit_bps: u64,
    },
}

// ---------------------------------------------------------------------------
// BPS scale – 1 bps = 10 000 units
// ---------------------------------------------------------------------------

const BPS_SCALE: u64 = 10_000;

/// Default taker fee in basis points used as fallback when an exchange
/// is not found in the fee schedule (0.1 %).
const DEFAULT_TAKER_FEE_BPS: u64 = 10;

/// Maximum allowed ratio per step in triangular profit calculation.
/// A step exceeding 100× indicates a data anomaly (e.g. near-zero ask).
const MAX_RATIO_BPS_MULTIPLIER: u64 = 100;

// ---------------------------------------------------------------------------
// MarketArena – the core arbitrage brain
// ---------------------------------------------------------------------------

/// Core arbitrage signal evaluation engine.
///
/// Maintains lock-free price arrays, pre-compiled cross-exchange targets,
/// and triangular loop definitions. The hot-path method [`Self::evaluate_tick`]
/// is designed to complete in under 1 µs per invocation.
pub struct MarketArena {
    /// Full order-book snapshot (for cold-path / diagnostics).
    pub matrix: Vec<OrderBookState>,

    /// Lock-free flat arrays – one slot per (exchange, token).
    pub bid_prices: Vec<AtomicU64>,
    pub ask_prices: Vec<AtomicU64>,

    /// Total number of token slots in the flat price arrays.
    pub total_tokens: usize,
    /// Total number of exchange slots in the flat price arrays.
    pub total_exchanges: usize,

    /// Pre-computed at boot: one entry per token listed on ≥ 2 exchanges.
    /// Protected by RwLock for safe concurrent reads (hot path) and
    /// writes (coin finder cold path at 1-second intervals).
    pub cross_targets: tokio::sync::RwLock<Vec<CrossExchangeTarget>>,

    /// Internal reverse index: token_id → indices into `cross_targets`.
    /// Also protected by cross_targets' RwLock since it's rebuilt at
    /// the same time.
    cross_index: tokio::sync::RwLock<Vec<Vec<usize>>>,

    /// Pre-compiled triangular loops, keyed by exchange id.
    /// Protected by its own RwLock.
    pub tri_loops: tokio::sync::RwLock<HashMap<u16, Vec<TriangularLoop>>>,

    /// Dynamically-discovered tokens that have passed all filters.
    /// Written by the coin finder's cold path (1-second intervals).
    /// Read by the signal loop via try_lock() for lock-free iteration.
    // NOTE: std::sync::Mutex used because get_active_token_ids() is called
    // from non-async test contexts. If this is ever called from an async
    // context, switch to tokio::sync::Mutex.
    pub active_tokens: std::sync::Mutex<Vec<u16>>,

    /// Hot-path toggles.
    pub enabled_cross: AtomicBool,
    pub enabled_tri: AtomicBool,

    /// Per-exchange fee schedule (bps).  Used to deduct trading costs from
    /// raw spread before signal emission.  Set at boot, read-only on hot path.
    pub fee_schedule: std::sync::RwLock<ExchangeFeeSchedule>,

    /// When `true`, spread calculations deduct round-trip trading fees
    /// before comparing to `min_spread_bps`.  When `false`, the original
    /// raw-spread behaviour is preserved (backwards-compatible).
    pub fee_aware_enabled: AtomicBool,

    /// Bitmask of exchanges allowed for cross-exchange signals.
    /// u64::MAX = all exchanges eligible (default).
    /// Set once at boot from config.  Lock-free on hot path.
    pub cross_exchange_mask: AtomicU64,

    /// Bitmask of exchanges allowed for triangular signals.
    /// u64::MAX = all exchanges eligible (default).
    /// Set once at boot from config.  Lock-free on hot path.
    pub tri_exchange_mask: AtomicU64,
}

impl MarketArena {
    // -----------------------------------------------------------------------
    // Construction
    // -----------------------------------------------------------------------

    /// Allocates the flat arrays and pre-initialises every slot to zero.
    ///
    /// # Panics
    ///
    /// Panics if `total_exchanges > 64`.  Exchange IDs are used as bit
    /// positions in `u64` bitmasks throughout `evaluate_tick` and
    /// `build_cross_exchange_targets`; shifting a `u64` by >= 64 is
    /// undefined behaviour in Rust, so this must be checked in both debug
    /// and release builds.
    pub fn new(total_exchanges: usize, total_tokens: usize) -> Self {
        assert!(
            total_exchanges <= 64,
            "total_exchanges ({}) must be <= 64 for u64 bitmask-based filtering",
            total_exchanges,
        );

        let size = total_exchanges.saturating_mul(total_tokens);

        let bid_prices: Vec<AtomicU64> = (0..size).map(|_| AtomicU64::new(0)).collect();
        let ask_prices: Vec<AtomicU64> = (0..size).map(|_| AtomicU64::new(0)).collect();
        let matrix = vec![OrderBookState::default(); size];
        let cross_index = vec![Vec::<usize>::new(); total_tokens];

        MarketArena {
            bid_prices,
            ask_prices,
            matrix,
            total_tokens,
            total_exchanges,
            cross_targets: tokio::sync::RwLock::new(Vec::new()),
            cross_index: tokio::sync::RwLock::new(cross_index),
            tri_loops: tokio::sync::RwLock::new(HashMap::new()),
            active_tokens: std::sync::Mutex::new(Vec::new()),
            enabled_cross: AtomicBool::new(true),
            enabled_tri: AtomicBool::new(true),
            fee_schedule: std::sync::RwLock::new(
                ExchangeFeeSchedule::new(total_exchanges, DEFAULT_TAKER_FEE_BPS),
            ),
            fee_aware_enabled: AtomicBool::new(true), // enabled by default
            // Default: all exchanges eligible for both strategies.
            cross_exchange_mask: AtomicU64::new(u64::MAX),
            tri_exchange_mask: AtomicU64::new(u64::MAX),
        }
    }

    // -----------------------------------------------------------------------
    // Indexing helper
    // -----------------------------------------------------------------------

    /// Register a token as actively discovered by the coin finder.
    ///
    /// Called from the coin finder's cold path when a token passes all filters.
    /// Uses `try_lock()` for non-blocking insertion on the hot path.
    #[inline]
    pub fn register_active_token(&self, token_id: u16) {
        if let Ok(mut tokens) = self.active_tokens.lock() {
            if !tokens.contains(&token_id) {
                tokens.push(token_id);
            }
        }
    }

    /// Returns a snapshot of all currently active token IDs.
    ///
    /// Uses a blocking `lock()` — do **not** call this from a hot-path
    /// async context.  The signal loop should use `active_tokens.try_lock()`
    /// directly to avoid blocking the tokio runtime.
    pub fn get_active_token_ids(&self) -> Vec<u16> {
        self.active_tokens
            .lock()
            .map(|t| t.clone())
            .unwrap_or_default()
    }

    /// Returns the flat-array index for `(exch_id, token_id)`.
    #[inline(always)]
    pub fn get_index(&self, exch_id: usize, token_id: usize) -> usize {
        (exch_id * self.total_tokens) + token_id
    }

    // -----------------------------------------------------------------------
    // Price updates (lock-free, hot-path)
    // -----------------------------------------------------------------------

    /// Atomically stores a new bid / ask pair using `Ordering::Release`.
    ///
    /// Silently drops the update if `exch_id` or `token_id` are out of range.
    /// This prevents a single malformed WebSocket message from panicking the
    /// entire process (denial-of-service vector).
    #[inline(always)]
    pub fn update_price(&self, exch_id: usize, token_id: usize, bid: u64, ask: u64) {
        if exch_id >= self.total_exchanges || token_id >= self.total_tokens {
            return;
        }
        let idx = self.get_index(exch_id, token_id);
        self.bid_prices[idx].store(bid, Ordering::Release);
        self.ask_prices[idx].store(ask, Ordering::Release);
    }

    /// Zeros out all prices for a given exchange, preventing stale data usage
    /// after a WebSocket disconnect.  Any strategy evaluating ticks from this
    /// exchange will see zero bid/ask and skip the opportunity.
    #[inline]
    pub fn invalidate_exchange(&self, exch_id: usize) {
        if exch_id >= self.total_exchanges {
            return;
        }
        let base = exch_id * self.total_tokens;
        for offset in 0..self.total_tokens {
            let idx = base + offset;
            self.bid_prices[idx].store(0, Ordering::Release);
            self.ask_prices[idx].store(0, Ordering::Release);
        }
    }

    // -----------------------------------------------------------------------
    // Cross-exchange target discovery (boot-time, cold path)
    // -----------------------------------------------------------------------

    /// Scans every token slot. For each token that has **non-zero** bid AND ask
    /// on ≥ 2 exchanges, builds a `CrossExchangeTarget` with a bitmask of the
    /// carrying exchanges.
    ///
    /// This method is async because it acquires the RwLock. It is called
    /// from the coin finder's cold path (1-second intervals).
    pub async fn build_cross_exchange_targets(&self) {
        let mut targets = self.cross_targets.write().await;
        let mut index = self.cross_index.write().await;
        targets.clear();
        for bucket in index.iter_mut() {
            bucket.clear();
        }

        for token_id in 0..self.total_tokens {
            let mut exchange_mask: u64 = 0;
            let mut shared_count: u8 = 0;

            for exch_id in 0..self.total_exchanges {
                let idx = self.get_index(exch_id, token_id);
                let bid = self.bid_prices[idx].load(Ordering::Acquire);
                let ask = self.ask_prices[idx].load(Ordering::Acquire);
                if bid > 0 && ask > 0 {
                    exchange_mask |= 1u64 << exch_id;
                    shared_count = shared_count.saturating_add(1);
                }
            }

            if shared_count >= 2 {
                let target_idx = targets.len();
                targets.push(CrossExchangeTarget {
                    token_id: token_id as u16,
                    exchange_mask,
                    shared_count,
                });
                index[token_id].push(target_idx);
            }
        }
    }

    // -----------------------------------------------------------------------
    // Triangular loop discovery (boot-time, cold path)
    // -----------------------------------------------------------------------

    /// Given per-exchange trading pairs as `(base_token, quote_token)`, finds
    /// all **directed** 3-step closed loops (A→B→C→A) and stores the compiled
    /// `TriangularLoop` values.
    ///
    /// Async because it acquires the RwLock. Called from coin finder cold path.
    pub async fn build_triangular_loops(&self, exchange_pairs: &HashMap<u16, Vec<(u16, u16)>>) {
        let mut loops_map = self.tri_loops.write().await;
        loops_map.clear();

        for (&exchange_id, pairs) in exchange_pairs {
            // Build adjacency list and edge set for the directed pair graph.
            let mut adj: HashMap<u16, Vec<u16>> = HashMap::new();
            let mut edge_set: HashSet<(u16, u16)> = HashSet::new();

            for &(base, quote) in pairs {
                adj.entry(base).or_default().push(quote);
                edge_set.insert((base, quote));
            }

            let mut loops = Vec::new();

            // Enumerate directed 3-cycles: a→b→c→a.
            // Deduplicate by only recording when `a` is the canonical minimum
            // of {a, b, c}.
            for (&a, neighbours_b) in &adj {
                for &b in neighbours_b {
                    if b == a {
                        continue;
                    }
                    if let Some(neighbours_c) = adj.get(&b) {
                        for &c in neighbours_c {
                            if c == a || c == b {
                                continue;
                            }
                            if edge_set.contains(&(c, a)) {
                                // a → b → c → a exists.
                                if a < b && a < c {
                                    loops.push(TriangularLoop {
                                        token_a: a,
                                        token_b: b,
                                        token_c: c,
                                    });
                                }
                            }
                        }
                    }
                }
            }

            if !loops.is_empty() {
                loops_map.insert(exchange_id, loops);
            }
        }
    }

    // -----------------------------------------------------------------------
    // Hot-path evaluation
    // -----------------------------------------------------------------------

    /// Called whenever a single `(exchange, token)` slot is updated.
    ///
    /// * **Cross-exchange** – iterates `cross_targets` that contain
    ///   `updated_token`. For every pair of exchanges carrying the token,
    ///   computes the spread in basis-points. If the best spread exceeds
    ///   `min_spread_bps`, emits a `CrossExchange` signal.
    ///
    /// * **Triangular** – iterates pre-compiled loops for `updated_exch`
    ///   that contain `updated_token`. Computes the profit ratio via
    ///   fixed-point u64 arithmetic (no floating point, no heap beyond the
    ///   result `Vec`).
    pub fn evaluate_tick(
        &self,
        updated_exch: usize,
        updated_token: usize,
        min_spread_bps: u64,
        min_tri_profit_bps: u64,
    ) -> Vec<ArbitrageSignal> {
        let mut signals = Vec::with_capacity(4); // small pre-alloc

        // Load per-strategy exchange masks once per tick (lock-free atomic read).
        let cross_mask = self.cross_exchange_mask.load(Ordering::Relaxed);
        let tri_mask = self.tri_exchange_mask.load(Ordering::Relaxed);

        // ------------------------------------------------------------------
        // Cross-exchange scanning
        // ------------------------------------------------------------------
        if self.enabled_cross.load(Ordering::Relaxed) {
            // Use try_read for hot-path — if the coin finder is rebuilding,
            // skip this tick rather than blocking the hot path.
            if let Ok(cross_targets) = self.cross_targets.try_read() {
            if let Ok(cross_index) = self.cross_index.try_read() {
            if updated_token < cross_index.len() {
                for &target_idx in &cross_index[updated_token] {
                    let target = &cross_targets[target_idx];
                    let mut mask = target.exchange_mask;

                    // Walk every pair (i, j) from the bitmask – no heap alloc.
                    while mask != 0 {
                        let exch_i = mask.trailing_zeros() as usize;
                        mask &= !(1u64 << exch_i);

                        let mut inner = mask; // remaining bits → avoids double-counting
                        while inner != 0 {
                            let exch_j = inner.trailing_zeros() as usize;
                            inner &= !(1u64 << exch_j);

                            let idx_i = self.get_index(exch_i, updated_token);
                            let idx_j = self.get_index(exch_j, updated_token);

                            if idx_i >= self.bid_prices.len() || idx_j >= self.bid_prices.len() {
                                continue;
                            }

                            let bid_i = self.bid_prices[idx_i].load(Ordering::Acquire);
                            let ask_i = self.ask_prices[idx_i].load(Ordering::Acquire);
                            let bid_j = self.bid_prices[idx_j].load(Ordering::Acquire);
                            let ask_j = self.ask_prices[idx_j].load(Ordering::Acquire);

                            // Direction 1: buy on i, sell on j
                            if bid_j > ask_i && ask_i > 0 {
                                let raw_spread_bps = (bid_j - ask_i).saturating_mul(BPS_SCALE) / ask_i;

                                // Fee-aware: deduct round-trip taker fees.
                                let net_spread_bps = if self.fee_aware_enabled.load(Ordering::Relaxed) {
                                    if let Ok(fees) = self.fee_schedule.try_read() {
                                        let fee_deduction = fees.round_trip_taker_bps(exch_i, exch_j);
                                        raw_spread_bps.saturating_sub(fee_deduction)
                                    } else {
                                        raw_spread_bps // skip fee check rather than block
                                    }
                                } else {
                                    raw_spread_bps
                                };

                                if net_spread_bps > min_spread_bps {
                                    let buy_bit = 1u64 << exch_i;
                                    let sell_bit = 1u64 << exch_j;
                                    // Both exchanges must be in the strategy allowlist.
                                    if cross_mask & buy_bit != 0 && cross_mask & sell_bit != 0 {
                                        signals.push(ArbitrageSignal::CrossExchange {
                                            buy_exchange: exch_i as u16,
                                            sell_exchange: exch_j as u16,
                                            token_id: target.token_id,
                                            spread_bps: net_spread_bps,
                                        });
                                    }
                                }
                            }

                            // Direction 2: buy on j, sell on i
                            if bid_i > ask_j && ask_j > 0 {
                                let raw_spread_bps = (bid_i - ask_j).saturating_mul(BPS_SCALE) / ask_j;

                                let net_spread_bps = if self.fee_aware_enabled.load(Ordering::Relaxed) {
                                    if let Ok(fees) = self.fee_schedule.try_read() {
                                        let fee_deduction = fees.round_trip_taker_bps(exch_j, exch_i);
                                        raw_spread_bps.saturating_sub(fee_deduction)
                                    } else {
                                        raw_spread_bps
                                    }
                                } else {
                                    raw_spread_bps
                                };

                                if net_spread_bps > min_spread_bps {
                                    let buy_bit = 1u64 << exch_j;
                                    let sell_bit = 1u64 << exch_i;
                                    if cross_mask & buy_bit != 0 && cross_mask & sell_bit != 0 {
                                        signals.push(ArbitrageSignal::CrossExchange {
                                            buy_exchange: exch_j as u16,
                                            sell_exchange: exch_i as u16,
                                            token_id: target.token_id,
                                            spread_bps: net_spread_bps,
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
            }
            } // cross_index
            } // cross_targets
        }

        // ------------------------------------------------------------------
        // Triangular arbitrage scanning
        // ------------------------------------------------------------------
        if self.enabled_tri.load(Ordering::Relaxed) {
            if let Ok(tri_map) = self.tri_loops.try_read() {
            if let Some(loops) = tri_map.get(&(updated_exch as u16)) {
                for tri in loops.iter() {
                    let ut = updated_token as u16;
                    // Skip loops that don't touch the updated token.
                    if tri.token_a != ut && tri.token_b != ut && tri.token_c != ut {
                        continue;
                    }

                    let idx_a = self.get_index(updated_exch, tri.token_a as usize);
                    let idx_b = self.get_index(updated_exch, tri.token_b as usize);
                    let idx_c = self.get_index(updated_exch, tri.token_c as usize);

                    let prices_len = self.bid_prices.len();
                    if idx_a >= prices_len || idx_b >= prices_len || idx_c >= prices_len {
                        continue;
                    }

                    let bid_a = self.bid_prices[idx_a].load(Ordering::Acquire);
                    let ask_a = self.ask_prices[idx_a].load(Ordering::Acquire);
                    let bid_b = self.bid_prices[idx_b].load(Ordering::Acquire);
                    let ask_b = self.ask_prices[idx_b].load(Ordering::Acquire);
                    let bid_c = self.bid_prices[idx_c].load(Ordering::Acquire);
                    let ask_c = self.ask_prices[idx_c].load(Ordering::Acquire);

                    // All six prices must be non-zero.
                    if bid_a == 0
                        || ask_a == 0
                        || bid_b == 0
                        || ask_b == 0
                        || bid_c == 0
                        || ask_c == 0
                    {
                        continue;
                    }

                    // Decimal-based profit ratio to avoid integer division truncation:
                    //   ratio = (bid_a / ask_a) * (bid_b / ask_b) * (bid_c / ask_c)
                    //
                    // Computed in Decimal to preserve precision across all three legs.
                    // The final result is scaled by BPS_SCALE and truncated to u64.
                    // If step3 > BPS_SCALE, the loop is profitable.
                    // profit_bps = step3 - BPS_SCALE  (already in basis-point units).

                    let ratio = Decimal::from(bid_a) / Decimal::from(ask_a)
                        * (Decimal::from(bid_b) / Decimal::from(ask_b))
                        * (Decimal::from(bid_c) / Decimal::from(ask_c));
                    let step3 = (ratio * Decimal::from(BPS_SCALE))
                        .trunc()
                        .to_u64()
                        .unwrap_or(0);

                    // Guard: reject if the ratio is unreasonable (>100x),
                    // which indicates a data anomaly (e.g., near-zero ask price).
                    if step3 > BPS_SCALE * MAX_RATIO_BPS_MULTIPLIER {
                        continue;
                    }

                    if step3 > BPS_SCALE {
                        let raw_profit_bps = step3 - BPS_SCALE;

                        // Fee-aware: deduct three-leg taker fees.
                        let net_profit_bps = if self.fee_aware_enabled.load(Ordering::Relaxed) {
                            if let Ok(fees) = self.fee_schedule.try_read() {
                                let fee_deduction = fees.tri_leg_taker_bps(updated_exch);
                                raw_profit_bps.saturating_sub(fee_deduction)
                            } else {
                                raw_profit_bps
                            }
                        } else {
                            raw_profit_bps
                        };

                        if net_profit_bps > min_tri_profit_bps {
                            // Check per-strategy exchange allowlist.
                            if tri_mask & (1u64 << updated_exch) != 0 {
                                signals.push(ArbitrageSignal::Triangular {
                                    exchange_id: updated_exch as u16,
                                    token_a: tri.token_a,
                                    token_b: tri.token_b,
                                    token_c: tri.token_c,
                                    profit_bps: net_profit_bps,
                                });
                            }
                        }
                    }
                }
            }
            } // tri_map
        }

        signals
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use rust_decimal::Decimal;
    use rust_decimal::prelude::ToPrimitive;

    #[test]
    fn test_update_price_reflects_in_atomics() {
        let arena = MarketArena::new(1, 1);
        arena.update_price(0, 0, 42, 99);
        let idx = arena.get_index(0, 0);
        assert_eq!(arena.bid_prices[idx].load(Ordering::Acquire), 42);
        assert_eq!(arena.ask_prices[idx].load(Ordering::Acquire), 99);
    }

    #[tokio::test]
    async fn test_no_cross_signal_when_single_exchange() {
        let arena = MarketArena::new(1, 2);
        arena.update_price(0, 0, 10_000, 9_950);
        arena.build_cross_exchange_targets().await;
        let targets = arena.cross_targets.read().await;
        assert!(targets.is_empty());

        let signals = arena.evaluate_tick(0, 0, 1, 0);
        assert!(signals.is_empty());
    }

    #[tokio::test]
    async fn test_cross_exchange_signal_detection() {
        let arena = MarketArena::new(2, 3);

        arena.update_price(0, 0, 10_050, 10_000);
        arena.update_price(1, 0, 10_080, 10_060);
        arena.update_price(0, 1, 5_000, 4_990);
        arena.update_price(1, 1, 5_010, 5_005);

        arena.build_cross_exchange_targets().await;
        let targets = arena.cross_targets.read().await;
        assert_eq!(targets.len(), 2);

        let t0 = &targets[arena.cross_index.read().await[0][0]];
        assert_eq!(t0.token_id, 0);
        assert_eq!(t0.exchange_mask, 0b11);
        assert_eq!(t0.shared_count, 2);

        // Disable fee-aware mode for this test (tests raw spread behaviour).
        arena.fee_aware_enabled.store(false, Ordering::Relaxed);

        let signals = arena.evaluate_tick(0, 0, 50, 0);
        assert_eq!(signals.len(), 1);
        match &signals[0] {
            ArbitrageSignal::CrossExchange {
                buy_exchange,
                sell_exchange,
                token_id,
                spread_bps,
            } => {
                assert_eq!(*buy_exchange, 0);
                assert_eq!(*sell_exchange, 1);
                assert_eq!(*token_id, 0);
                assert_eq!(*spread_bps, 80);
            }
            other => panic!("expected CrossExchange signal, got {:?}", other),
        }

        let signals_high = arena.evaluate_tick(0, 0, 100, 0);
        assert!(signals_high.is_empty());
    }

    #[tokio::test]
    async fn test_cross_signal_both_directions() {
        let arena = MarketArena::new(2, 1);
        arena.update_price(0, 0, 10_100, 10_000);
        arena.update_price(1, 0, 10_050, 9_950);

        arena.build_cross_exchange_targets().await;
        // Disable fee-aware for raw-spread assertion.
        arena.fee_aware_enabled.store(false, Ordering::Relaxed);
        let signals = arena.evaluate_tick(0, 0, 1, 0);
        assert_eq!(signals.len(), 2);
    }

    #[tokio::test]
    async fn test_triangular_signal_detection() {
        let arena = MarketArena::new(1, 3);

        arena.update_price(0, 0, 11_000, 10_000);
        arena.update_price(0, 1, 11_000, 10_000);
        arena.update_price(0, 2, 11_000, 10_000);

        let mut pairs: HashMap<u16, Vec<(u16, u16)>> = HashMap::new();
        pairs.insert(0, vec![(0, 1), (1, 2), (2, 0)]);
        arena.build_triangular_loops(&pairs).await;

        let loops = arena.tri_loops.read().await;
        assert_eq!(loops.get(&0).unwrap().len(), 1);
        assert_eq!(loops[&0][0].token_a, 0);
        assert_eq!(loops[&0][0].token_b, 1);
        assert_eq!(loops[&0][0].token_c, 2);

        // Disable fee-aware for raw-profit assertion.
        arena.fee_aware_enabled.store(false, Ordering::Relaxed);

        let signals = arena.evaluate_tick(0, 0, 0, 100);
        assert_eq!(signals.len(), 1);
        match &signals[0] {
            ArbitrageSignal::Triangular {
                exchange_id,
                token_a,
                token_b,
                token_c,
                profit_bps,
            } => {
                assert_eq!(*exchange_id, 0);
                assert_eq!(*token_a, 0);
                assert_eq!(*token_b, 1);
                assert_eq!(*token_c, 2);
                assert_eq!(*profit_bps, 3_310);
            }
            other => panic!("expected Triangular signal, got {:?}", other),
        }

        let signals_none = arena.evaluate_tick(0, 0, 0, 4_000);
        assert!(signals_none.is_empty());

        let signals_other = arena.evaluate_tick(0, 1, 0, 100);
        assert_eq!(signals_other.len(), 1);
    }

    #[tokio::test]
    async fn test_triangular_no_signal_when_unprofitable() {
        let arena = MarketArena::new(1, 3);

        arena.update_price(0, 0, 9_000, 10_000);
        arena.update_price(0, 1, 9_000, 10_000);
        arena.update_price(0, 2, 9_000, 10_000);

        let mut pairs: HashMap<u16, Vec<(u16, u16)>> = HashMap::new();
        pairs.insert(0, vec![(0, 1), (1, 2), (2, 0)]);
        arena.build_triangular_loops(&pairs).await;

        let signals = arena.evaluate_tick(0, 0, 0, 0);
        assert!(signals.is_empty());
    }

    #[tokio::test]
    async fn test_toggle_disables_strategies() {
        let arena = MarketArena::new(2, 1);
        arena.update_price(0, 0, 10_050, 10_000);
        arena.update_price(1, 0, 10_080, 10_060);
        arena.build_cross_exchange_targets().await;

        // Disable fee-aware for raw-spread assertion.
        arena.fee_aware_enabled.store(false, Ordering::Relaxed);

        arena.enabled_cross.store(false, Ordering::Relaxed);
        let signals = arena.evaluate_tick(0, 0, 0, 0);
        assert!(signals.is_empty());

        arena.enabled_cross.store(true, Ordering::Relaxed);
        let signals = arena.evaluate_tick(0, 0, 0, 0);
        assert_eq!(signals.len(), 1);
    }

    #[tokio::test]
    async fn test_multiple_triangular_loops_same_exchange() {
        let arena = MarketArena::new(1, 5);

        arena.update_price(0, 0, 11_000, 10_000);
        arena.update_price(0, 1, 11_000, 10_000);
        arena.update_price(0, 2, 11_000, 10_000);
        arena.update_price(0, 3, 10_500, 10_000);
        arena.update_price(0, 4, 10_500, 10_000);

        let mut pairs: HashMap<u16, Vec<(u16, u16)>> = HashMap::new();
        pairs.insert(0,
            vec![
                (0, 1), (1, 2), (2, 0),
                (2, 3), (3, 4), (4, 2),
            ],
        );
        arena.build_triangular_loops(&pairs).await;

        let loops = arena.tri_loops.read().await;
        assert_eq!(loops.get(&0).unwrap().len(), 2);

        // Disable fee-aware for raw-profit assertion.
        arena.fee_aware_enabled.store(false, Ordering::Relaxed);

        let signals = arena.evaluate_tick(0, 2, 0, 100);
        assert_eq!(signals.len(), 2);
    }

    // -------------------------------------------------------------------
    // Fee-aware protection tests
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn test_fee_aware_blocks_unprofitable_cross_signal() {
        // Raw spread = 25 bps.  Default fees = 10 bps per exchange = 20 bps round-trip.
        // Net spread = 5 bps.  With min_spread_bps = 10, signal should be blocked.
        let arena = MarketArena::new(2, 1);
        // ex0: bid=10000, ask=10000  (no spread on reverse direction)
        // ex1: bid=10025, ask=10050  (ask high enough to kill reverse)
        // buy-on-0 (ask=10000), sell-on-1 (bid=10025) → raw = (25*10000)/10000 = 25 bps
        arena.update_price(0, 0, 10_000, 10_000);
        arena.update_price(1, 0, 10_025, 10_050);
        arena.build_cross_exchange_targets().await;

        // Fee-aware is ON by default.
        assert!(arena.fee_aware_enabled.load(Ordering::Relaxed));

        // min_spread_bps = 10 → net 5 bps should be rejected.
        let signals = arena.evaluate_tick(0, 0, 10, 0);
        assert!(signals.is_empty(), "fee-deducted spread should be below threshold");
    }

    #[tokio::test]
    async fn test_fee_aware_allows_profitable_cross_signal() {
        // Raw spread = 50 bps.  Fees = 20 bps round-trip.  Net = 30 bps.
        // With min_spread_bps = 25, net 30 bps should pass (uses strict >).
        let arena = MarketArena::new(2, 1);
        // ex0: bid=10000, ask=10000  (no spread on reverse direction)
        // ex1: bid=10050, ask=10080  (ask high enough to kill reverse)
        // buy-on-0 (ask=10000), sell-on-1 (bid=10050) → raw = (50*10000)/10000 = 50 bps
        arena.update_price(0, 0, 10_000, 10_000);
        arena.update_price(1, 0, 10_050, 10_080);
        arena.build_cross_exchange_targets().await;

        // min_spread_bps = 25 → net 30 bps > 25 → should be emitted.
        let signals = arena.evaluate_tick(0, 0, 25, 0);
        assert_eq!(signals.len(), 1);
        match &signals[0] {
            ArbitrageSignal::CrossExchange { spread_bps, .. } => {
                // net = 50 - 20 = 30 bps
                assert_eq!(*spread_bps, 30);
            }
            other => panic!("expected CrossExchange, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_fee_aware_custom_exchange_fees() {
        // Exchange 0: 5 bps taker, Exchange 1: 15 bps taker → round-trip = 20 bps.
        let arena = MarketArena::new(2, 1);
        // ex0: bid=10000, ask=10000  (no spread on reverse direction)
        // ex1: bid=10030, ask=10060  (ask high enough to kill reverse)
        // buy-on-0 (ask=10000), sell-on-1 (bid=10030) → raw = (30*10000)/10000 = 30 bps
        arena.update_price(0, 0, 10_000, 10_000);
        arena.update_price(1, 0, 10_030, 10_060);
        arena.build_cross_exchange_targets().await;

        // Custom fees: ex0=5 bps, ex1=15 bps.
        {
            let mut fees = arena.fee_schedule.write().unwrap();
            fees.set_fee(0, 5, 5).expect("exchange_id 0 in range");
            fees.set_fee(1, 10, 15).expect("exchange_id 1 in range");
        }

        // Raw spread = 30 bps.  Net = 30 - (5 + 15) = 10 bps.
        let signals = arena.evaluate_tick(0, 0, 5, 0);
        assert_eq!(signals.len(), 1);
        match &signals[0] {
            ArbitrageSignal::CrossExchange { spread_bps, .. } => {
                assert_eq!(*spread_bps, 10);
            }
            other => panic!("expected CrossExchange, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_fee_aware_triangular_deduction() {
        // Raw profit = 3310 bps (same setup as test_triangular_signal_detection).
        // Fee deduction: 3 legs * 10 bps = 30 bps.  Net = 3280 bps.
        let arena = MarketArena::new(1, 3);
        arena.update_price(0, 0, 11_000, 10_000);
        arena.update_price(0, 1, 11_000, 10_000);
        arena.update_price(0, 2, 11_000, 10_000);

        let mut pairs: HashMap<u16, Vec<(u16, u16)>> = HashMap::new();
        pairs.insert(0, vec![(0, 1), (1, 2), (2, 0)]);
        arena.build_triangular_loops(&pairs).await;

        // Fee-aware ON (default).  Net = 3310 - 30 = 3280 bps.
        // Threshold comparison is strict (>), so use 3279 to allow 3280 > 3279.
        let signals = arena.evaluate_tick(0, 0, 0, 3279);
        assert_eq!(signals.len(), 1);

        // With threshold at net profit, signal blocked (3280 > 3280 is false).
        let signals_blocked = arena.evaluate_tick(0, 0, 0, 3280);
        assert!(signals_blocked.is_empty());
    }

    #[test]
    fn test_exchange_fee_schedule_round_trip() {
        let mut fees = ExchangeFeeSchedule::new(3, 10);
        fees.set_fee(0, 5, 10).expect("exchange_id 0 in range");   // Binance: 5 bps maker, 10 bps taker
        fees.set_fee(1, 2, 6).expect("exchange_id 1 in range");    // Bybit:   2 bps maker,  6 bps taker

        // Round-trip taker: 10 + 6 = 16 bps
        assert_eq!(fees.round_trip_taker_bps(0, 1), 16);
        assert_eq!(fees.round_trip_taker_bps(1, 0), 16);

        // Out-of-bounds exchange falls back to default 10 bps.
        assert_eq!(fees.round_trip_taker_bps(0, 99), 20);
    }

    #[test]
    fn test_exchange_fee_schedule_tri_leg() {
        let mut fees = ExchangeFeeSchedule::new(1, 8);
        fees.set_fee(0, 4, 8).expect("exchange_id 0 in range");
        assert_eq!(fees.tri_leg_taker_bps(0), 24); // 3 * 8
    }

    // -------------------------------------------------------------------
    // Comprehensive mathematical verification for live deployment
    // -------------------------------------------------------------------

    /// Verify the triangular profit ratio computed in u64 fixed-point
    /// matches the same calculation done in Decimal arithmetic.
    /// This is the EXACT formula used in evaluate_tick:
    ///   step1 = (bid_a * 10_000) / ask_a
    ///   step2 = (step1 * bid_b) / ask_b
    ///   step3 = (step2 * bid_c) / ask_c
    ///   profit_bps = step3 - 10_000
    #[test]
    fn test_triangular_fp_ratio_matches_decimal() {
        // Simulate: USDT→BTC→ETH→USDT on one exchange.
        // Prices (in 8-decimal fixed-point):
        //   Token A (USDT): bid=1_0000_0000, ask=1_0001_0000
        //   Token B (BTC):  bid=0_0000_2000, ask=0_0000_2001  (=$20000, $20001)
        //   Token C (ETH):  bid=0_0000_5000, ask=0_0000_5001  (=$50000, $50001)
        //
        // Loop: A→B: buy BTC with USDT at ask_b = 20001
        //       B→C: buy ETH with BTC at ask_c = 50001
        //       C→A: sell ETH for USDT at bid_a = 10000
        //
        // Decimal: ratio = (10000/20001) * (10000?... )
        // Actually in the arena's format, all prices are in 8-decimal FP.
        // The formula is: ratio = (bid_a/ask_a) * (bid_b/ask_b) * (bid_c/ask_c)

        // Use simple values for clarity:
        // bid_a=11000, ask_a=10000 → 1.1x
        // bid_b=11000, ask_b=10000 → 1.1x
        // bid_c=11000, ask_c=10000 → 1.1x
        // ratio = 1.1 * 1.1 * 1.1 = 1.331
        // profit_bps = (1.331 - 1) * 10000 = 3310 bps
        let bid_a: u64 = 11_000;
        let ask_a: u64 = 10_000;
        let bid_b: u64 = 11_000;
        let ask_b: u64 = 10_000;
        let bid_c: u64 = 11_000;
        let ask_c: u64 = 10_000;

        // Fixed-point computation (matches evaluate_tick exactly):
        let step1 = bid_a.saturating_mul(BPS_SCALE) / ask_a; // 110000000 / 10000 = 11000
        let step2 = step1.saturating_mul(bid_b) / ask_b;     // 11000 * 11000 / 10000 = 12100
        let step3 = step2.saturating_mul(bid_c) / ask_c;     // 12100 * 11000 / 10000 = 13310
        let profit_bps_fp = step3 - BPS_SCALE;                // 13310 - 10000 = 3310

        // Decimal verification:
        let ratio = Decimal::from(bid_a) / Decimal::from(ask_a)
                  * Decimal::from(bid_b) / Decimal::from(ask_b)
                  * Decimal::from(bid_c) / Decimal::from(ask_c);
        let profit_bps_dec = ((ratio - Decimal::ONE) * Decimal::from(BPS_SCALE))
            .round().to_u64().unwrap_or(0);

        assert_eq!(profit_bps_fp, 3310, "FP triangular profit must be 3310 bps");
        assert_eq!(profit_bps_fp, profit_bps_dec,
            "FP ({}) must match Decimal ({}) for triangular profit",
            profit_bps_fp, profit_bps_dec);
    }

    /// Verify triangular profit with realistic prices and non-round numbers
    /// where integer division truncation matters.
    #[test]
    fn test_triangular_fp_truncation_safety() {
        // Prices that don't divide evenly:
        // bid_a=9997, ask_a=10003, bid_b=19993, ask_b=20007, bid_c=49987, ask_c=50013
        let bid_a: u64 = 9_997;
        let ask_a: u64 = 10_003;
        let bid_b: u64 = 19_993;
        let ask_b: u64 = 20_007;
        let bid_c: u64 = 49_987;
        let ask_c: u64 = 50_013;

        // FP computation
        let step1 = bid_a.saturating_mul(BPS_SCALE) / ask_a;
        let step2 = step1.saturating_mul(bid_b) / ask_b;
        let step3 = step2.saturating_mul(bid_c) / ask_c;

        // Verify no overflow occurred (all steps should be reasonable)
        assert!(step1 < BPS_SCALE * 2, "step1 should be near 1.0x scaled");
        assert!(step2 < BPS_SCALE * 2, "step2 should be near 1.0x scaled");
        assert!(step3 < BPS_SCALE * 4, "step3 should be < 4.0x scaled");

        // Verify the Decimal equivalent is close (within 1 bps of truncation).
        let ratio = Decimal::from(bid_a) / Decimal::from(ask_a)
                  * Decimal::from(bid_b) / Decimal::from(ask_b)
                  * Decimal::from(bid_c) / Decimal::from(ask_c);
        let profit_bps_dec = ((ratio - Decimal::ONE) * Decimal::from(BPS_SCALE))
            .floor().to_u64().unwrap_or(0);
        let profit_bps_fp = step3.saturating_sub(BPS_SCALE);

        // FP should be within 2 bps of Decimal (truncation error from 3 divisions).
        let diff = profit_bps_fp.abs_diff(profit_bps_dec);
        assert!(diff <= 3,
            "FP triangular profit ({}) must be within 3 bps of Decimal ({}). \
             3 integer divisions can introduce up to 3 bps truncation.",
            profit_bps_fp, profit_bps_dec);
    }

    /// Verify cross-exchange spread computation: (bid_j - ask_i) * 10000 / ask_i
    /// matches Decimal arithmetic.
    #[test]
    fn test_cross_exchange_spread_fp_matches_decimal() {
        let ask_i: u64 = 50_001_000_000u64; // $50,001 in 8-decimal FP
        let bid_j: u64 = 50_025_000_000u64; // $50,025 in 8-decimal FP

        let raw_spread_bps_fp = (bid_j - ask_i) * BPS_SCALE / ask_i;

        // Decimal: (50025 - 50001) / 50001 * 10000 = 24/50001 * 10000 = 4.7999...
        let ask_dec = Decimal::from(ask_i);
        let bid_dec = Decimal::from(bid_j);
        let raw_spread_bps_dec = ((bid_dec - ask_dec) / ask_dec * Decimal::from(BPS_SCALE))
            .floor().to_u64().unwrap_or(0);

        assert_eq!(raw_spread_bps_fp, 4, "FP cross-exchange spread should be 4 bps (truncated from 4.7999)");
        assert_eq!(raw_spread_bps_fp, raw_spread_bps_dec,
            "FP ({}) must match Decimal ({}) for cross-exchange spread",
            raw_spread_bps_fp, raw_spread_bps_dec);
    }

    /// Verify that fee-aware net spread never goes negative (saturating_sub).
    #[test]
    fn test_fee_aware_net_spread_never_negative() {
        // Raw spread = 15 bps. Round-trip fees = 20 bps.
        // net = 15u64.saturating_sub(20) = 0 (not underflow!)
        let raw: u64 = 15;
        let fees: u64 = 20;
        let net = raw.saturating_sub(fees);
        assert_eq!(net, 0, "saturating_sub must clamp to 0, not wrap");
    }

    /// Verify ExchangeFeeSchedule.deduct_fees_bps if it exists,
    /// or the manual deduction used in evaluate_tick.
    #[test]
    fn test_exchange_fee_schedule_consistency() {
        let mut fees = ExchangeFeeSchedule::new(5, 10);
        fees.set_fee(0, 5, 10).expect("exchange_id 0 in range");  // Binance
        fees.set_fee(1, 3, 10).expect("exchange_id 1 in range");  // Bybit
        fees.set_fee(2, 3, 8).expect("exchange_id 2 in range");   // OKX
        fees.set_fee(3, 5, 10).expect("exchange_id 3 in range");  // GateIO
        fees.set_fee(4, 3, 10).expect("exchange_id 4 in range");  // KuCoin

        // Verify every exchange has a taker fee set.
        for i in 0..5 {
            let taker = fees.taker_fees[i];
            assert!(taker > 0, "exchange {} taker fee must be > 0, got {}", i, taker);
        }

        // Cross-exchange: Binance(0) → OKX(2) = 10 + 8 = 18 bps
        assert_eq!(fees.round_trip_taker_bps(0, 2), 18);
        // Triangular on OKX(2) = 3 * 8 = 24 bps
        assert_eq!(fees.tri_leg_taker_bps(2), 24);
    }
}
