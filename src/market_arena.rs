//! Market Arena — Shared Price Matrix with Exchange Bitmasks
//!
//! The spec defines:
//! - `MarketArena` — Central in-memory order book matrix (RwLock for all exchanges×tokens)
//! - `OrderBookState` — Compact order book snapshot (bid_price, ask_price as u64)
//! - `CrossExchangeTarget` — Token with bitmask of which exchanges carry it
//!
//! The per-strategy exchange routing uses atomic bitmasks: each strategy
//! maintains a bitmask of which exchanges it's allowed to trade on.

use std::sync::RwLock;

/// Compact order book snapshot — Copy for zero-copy passing.
///
/// The spec uses `u64` for prices to avoid Decimal on the hot path.
/// Prices are stored as fixed-point with 9 decimal places:
/// `actual_price = stored_value / 1_000_000_000`
#[derive(Debug, Clone, Copy, Default)]
pub struct OrderBookState {
    /// Best bid price (fixed-point, 9 decimals).
    pub bid_price: u64,
    /// Best ask price (fixed-point, 9 decimals).
    pub ask_price: u64,
    /// Timestamp of last update (ms since epoch).
    pub timestamp_ms: u64,
    /// Sequence number for change detection.
    pub sequence: u64,
}

impl OrderBookState {
    /// Creates a new state.
    pub fn new(bid_fp: u64, ask_fp: u64) -> Self {
        Self {
            bid_price: bid_fp,
            ask_price: ask_fp,
            timestamp_ms: chrono::Utc::now().timestamp_millis() as u64,
            sequence: 0,
        }
    }

    /// Compute the mid-price as fixed-point.
    #[inline(always)]
    pub fn mid_price_fp(&self) -> u64 {
        (self.bid_price + self.ask_price) / 2
    }

    /// Compute the spread in fixed-point.
    #[inline(always)]
    pub fn spread_fp(&self) -> u64 {
        self.ask_price.saturating_sub(self.bid_price)
    }
}

/// A token tracked across multiple exchanges.
///
/// The `exchange_mask` is a bitmask where bit N is set if exchange N
/// carries this token. This enables per-strategy routing.
///
/// Example: if exchanges 0 (Binance), 2 (OKX), and 5 (KuCoin) carry SOL,
/// then `exchange_mask = 0b100101 = 37`.
#[derive(Debug, Clone)]
pub struct CrossExchangeTarget {
    /// Token symbol (e.g. "SOLUSDT").
    pub symbol: String,
    /// Bitmask of exchanges that carry this token.
    pub exchange_mask: u64,
    /// Token ID for matrix indexing.
    pub token_id: usize,
}

impl CrossExchangeTarget {
    /// Creates a new target.
    pub fn new(symbol: &str, token_id: usize) -> Self {
        Self {
            symbol: symbol.to_uppercase(),
            exchange_mask: 0,
            token_id,
        }
    }

    /// Add an exchange to the bitmask.
    #[inline]
    pub fn add_exchange(&mut self, exchange_id: u16) {
        if exchange_id < 64 {
            self.exchange_mask |= 1u64 << exchange_id;
        }
    }

    /// Remove an exchange from the bitmask.
    #[inline]
    pub fn remove_exchange(&mut self, exchange_id: u16) {
        if exchange_id < 64 {
            self.exchange_mask &= !(1u64 << exchange_id);
        }
    }

    /// Check if an exchange carries this token.
    #[inline(always)]
    pub fn has_exchange(&self, exchange_id: u16) -> bool {
        if exchange_id >= 64 {
            return false;
        }
        (self.exchange_mask & (1u64 << exchange_id)) != 0
    }

    /// Count the number of exchanges that carry this token.
    pub fn exchange_count(&self) -> u32 {
        self.exchange_mask.count_ones()
    }
}

/// Central in-memory order book matrix for all exchange×token combinations.
///
/// Provides O(1) access to the latest order book state via flat indexing:
/// `index = exchange_id * num_tokens + token_id`
pub struct MarketArena {
    /// The price matrix: rows = exchanges, cols = tokens.
    matrix: Vec<RwLock<OrderBookState>>,
    /// Number of exchanges.
    num_exchanges: usize,
    /// Number of tokens.
    num_tokens: usize,
    /// Cross-exchange targets with their bitmasks.
    targets: Vec<CrossExchangeTarget>,
    /// M-20: Maximum number of cross-exchange targets. When exceeded,
    /// the oldest target is evicted to prevent unbounded memory growth.
    max_targets: usize,
}

impl MarketArena {
    /// Creates a new market arena.
    ///
    /// # Arguments
    /// * `num_exchanges` — Number of exchanges to track
    /// * `num_tokens` — Number of tokens/pairs to track
    pub fn new(num_exchanges: usize, num_tokens: usize) -> Self {
        let total_slots = num_exchanges * num_tokens;
        let matrix = (0..total_slots)
            .map(|_| RwLock::new(OrderBookState::default()))
            .collect();

        Self {
            matrix,
            num_exchanges,
            num_tokens,
            targets: Vec::new(),
            max_targets: 10_000, // M-20: default max entries
        }
    }

    /// Compute flat index: `exchange_id * num_tokens + token_id`.
    #[inline(always)]
    pub fn get_index(&self, exchange_id: usize, token_id: usize) -> usize {
        let idx = exchange_id * self.num_tokens + token_id;
        debug_assert!(idx < self.matrix.len(), "arena index out of bounds: exchange={}, token={}", exchange_id, token_id);
        idx
    }

    /// Update the order book state for a specific exchange×token.
    ///
    /// If the lock is poisoned (a previous holder panicked), the poisoned
    /// state is recovered and the update proceeds.  This prevents a single
    /// panic from permanently disabling the entire arena.
    #[inline]
    pub fn update(&self, exchange_id: usize, token_id: usize, bid_fp: u64, ask_fp: u64) {
        let idx = self.get_index(exchange_id, token_id);
        if let Some(slot) = self.matrix.get(idx) {
            let mut state = slot.write().unwrap_or_else(|poisoned| {
                tracing::warn!(
                    exchange_id, token_id,
                    "RwLock poisoned in MarketArena::update — recovering"
                );
                poisoned.into_inner()
            });
            state.bid_price = bid_fp;
            state.ask_price = ask_fp;
            state.timestamp_ms = chrono::Utc::now().timestamp_millis() as u64;
            state.sequence = state.sequence.wrapping_add(1);
        } else {
            tracing::warn!(
                exchange_id, token_id, idx,
                "MarketArena::update: index out of bounds, write dropped"
            );
        }
    }

    /// Read the order book state for a specific exchange×token.
    /// Returns a copy (zero-copy read via RwLock).
    ///
    /// If the lock is poisoned, the poisoned value is recovered and returned.
    #[inline]
    pub fn read(&self, exchange_id: usize, token_id: usize) -> Option<OrderBookState> {
        let idx = self.get_index(exchange_id, token_id);
        self.matrix.get(idx).map(|slot| {
            *slot.read().unwrap_or_else(|poisoned| {
                tracing::warn!(
                    exchange_id, token_id,
                    "RwLock poisoned in MarketArena::read — recovering"
                );
                poisoned.into_inner()
            })
        })
    }

    /// Register a cross-exchange target.
    ///
    /// M-20: If the number of targets exceeds `max_targets`, the oldest
    /// target is evicted to prevent unbounded memory growth.
    pub fn register_target(&mut self, target: CrossExchangeTarget) {
        if self.targets.len() >= self.max_targets {
            tracing::warn!(
                max = self.max_targets,
                evicted_token = %self.targets.first().map(|t| t.symbol.as_str()).unwrap_or("?"),
                "M-20: market_arena target limit reached, evicting oldest"
            );
            self.targets.remove(0);
        }
        self.targets.push(target);
    }

    /// Get a target by token ID.
    pub fn get_target(&self, token_id: usize) -> Option<&CrossExchangeTarget> {
        self.targets.iter().find(|t| t.token_id == token_id)
    }

    /// Get all targets.
    pub fn targets(&self) -> &[CrossExchangeTarget] {
        &self.targets
    }

    /// Number of exchanges.
    pub fn num_exchanges(&self) -> usize {
        self.num_exchanges
    }

    /// Number of tokens.
    pub fn num_tokens(&self) -> usize {
        self.num_tokens
    }

    /// Total matrix size.
    pub fn matrix_size(&self) -> usize {
        self.matrix.len()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn fp(price: f64) -> u64 {
        (price * 1_000_000_000.0) as u64
    }

    #[test]
    fn test_order_book_state() {
        let state = OrderBookState::new(fp(100.0), fp(100.5));
        assert_eq!(state.bid_price, fp(100.0));
        assert_eq!(state.ask_price, fp(100.5));
        assert_eq!(state.mid_price_fp(), (fp(100.0) + fp(100.5)) / 2);
    }

    #[test]
    fn test_cross_exchange_target_bitmask() {
        let mut target = CrossExchangeTarget::new("SOLUSDT", 0);
        target.add_exchange(0); // Binance
        target.add_exchange(2); // OKX
        target.add_exchange(5); // KuCoin

        assert!(target.has_exchange(0));
        assert!(!target.has_exchange(1));
        assert!(target.has_exchange(2));
        assert!(target.has_exchange(5));
        assert_eq!(target.exchange_count(), 3);
    }

    #[test]
    fn test_cross_exchange_target_remove() {
        let mut target = CrossExchangeTarget::new("BTCUSDT", 0);
        target.add_exchange(0);
        target.add_exchange(1);
        assert!(target.has_exchange(0));
        target.remove_exchange(0);
        assert!(!target.has_exchange(0));
        assert_eq!(target.exchange_count(), 1);
    }

    #[test]
    fn test_market_arena_update_read() {
        let arena = MarketArena::new(3, 5);
        arena.update(0, 0, fp(50000.0), fp(50001.0));
        let state = arena.read(0, 0).unwrap();
        assert_eq!(state.bid_price, fp(50000.0));
        assert_eq!(state.ask_price, fp(50001.0));
    }

    #[test]
    fn test_market_arena_index() {
        let arena = MarketArena::new(3, 5);
        // exchange 1, token 2 → 1*5 + 2 = 7
        assert_eq!(arena.get_index(1, 2), 7);
    }

    #[test]
    fn test_market_arena_register_target() {
        let mut arena = MarketArena::new(3, 5);
        let mut target = CrossExchangeTarget::new("SOLUSDT", 0);
        target.add_exchange(0);
        target.add_exchange(1);
        arena.register_target(target);
        assert_eq!(arena.targets().len(), 1);
    }

    #[test]
    fn test_market_arena_size() {
        let arena = MarketArena::new(17, 100);
        assert_eq!(arena.num_exchanges(), 17);
        assert_eq!(arena.num_tokens(), 100);
        assert_eq!(arena.matrix_size(), 1700);
    }
}