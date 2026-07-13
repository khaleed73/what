use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

use rust_decimal::Decimal;

// ---------------------------------------------------------------------------
// Token category bitmask constants
// ---------------------------------------------------------------------------

pub const CAT_NONE: u16 = 0b0000_0000;
pub const CAT_MAJOR: u16 = 0b0000_0001; // BTC, ETH
pub const CAT_ALTCOIN: u16 = 0b0000_0010; // SOL, ADA, DOT
pub const CAT_MEMECOIN: u16 = 0b0000_0100; // DOGE, PEPE
pub const CAT_STABLE: u16 = 0b0000_1000; // USDT, USDC
pub const CAT_LAYER1: u16 = 0b0001_0000; // AVAX, NEAR

// ---------------------------------------------------------------------------
// Fixed-point conversion helpers
// ---------------------------------------------------------------------------

const FP_SCALE: u64 = 1_000_000;

/// Convert a `Decimal` to a fixed-point `u64` (truncated).
/// Value = d * 1_000_000
fn decimal_to_fp(d: Decimal) -> u64 {
    // Decimal * 1_000_000, truncated toward zero
    let scaled = d * Decimal::from(FP_SCALE);
    // to_string avoids overflow that .trunc_with_scale(0).to_u64() might hit;
    // we round toward zero manually.
    let neg = scaled < Decimal::ZERO;
    let abs = if neg { -scaled } else { scaled };
    let s = abs.to_string();
    // Find the decimal point if present
    let truncated_str = if let Some(dot) = s.find('.') {
        // Keep only the integer part
        &s[..dot]
    } else {
        &s
    };
    let val: u64 = truncated_str.parse().unwrap_or(0);
    if neg { val.wrapping_neg() } else { val }
}

/// Convert a fixed-point `u64` back to a `Decimal`.
/// Decimal = fp / 1_000_000
fn fp_to_decimal(fp: u64) -> Decimal {
    Decimal::from(fp) / Decimal::from(FP_SCALE)
}

// ---------------------------------------------------------------------------
// TokenAsset
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct TokenAsset {
    pub id: u16,
    pub symbol: String,
    pub category_mask: u16,
}

// ---------------------------------------------------------------------------
// CategorizedInventory
// ---------------------------------------------------------------------------

pub struct CategorizedInventory {
    pub token_registry: HashMap<u16, TokenAsset>,
    pub symbol_to_id: HashMap<String, u16>,
    pub memecoin_indices: Vec<u16>,
    pub altcoin_indices: Vec<u16>,
    pub major_indices: Vec<u16>,
    pub stable_indices: Vec<u16>,
}

impl CategorizedInventory {
    pub fn new() -> Self {
        Self {
            token_registry: HashMap::new(),
            symbol_to_id: HashMap::new(),
            memecoin_indices: Vec::new(),
            altcoin_indices: Vec::new(),
            major_indices: Vec::new(),
            stable_indices: Vec::new(),
        }
    }

    pub fn register_token(&mut self, id: u16, symbol: &str, mask: u16) {
        self.symbol_to_id.insert(symbol.to_uppercase(), id);
        self.token_registry.insert(
            id,
            TokenAsset {
                id,
                symbol: symbol.to_uppercase(),
                category_mask: mask,
            },
        );

        if mask & CAT_MEMECOIN != 0 {
            self.memecoin_indices.push(id);
        }
        if mask & CAT_ALTCOIN != 0 {
            self.altcoin_indices.push(id);
        }
        if mask & CAT_MAJOR != 0 {
            self.major_indices.push(id);
        }
        if mask & CAT_STABLE != 0 {
            self.stable_indices.push(id);
        }
    }
}

// ---------------------------------------------------------------------------
// LocalCapitalAllocator
// ---------------------------------------------------------------------------

pub struct LocalCapitalAllocator {
    /// Flat array indexed as `[exchange_id * total_tokens + token_id]`.
    /// Each slot stores a fixed-point representation of the balance
    /// (actual value * 1_000_000) in an `AtomicU64`.
    pub balances: Vec<AtomicU64>,
    pub total_tokens: usize,
    pub total_exchanges: usize,
    /// Token registry wrapped in a Mutex for interior mutability.
    /// The coin finder registers new tokens from a background task;
    /// hot-path readers acquire the lock briefly to look up symbols.
    pub inventory: std::sync::Mutex<CategorizedInventory>,
}

impl LocalCapitalAllocator {
    /// Creates a new allocator with the given number of exchanges and tokens.
    /// All balances are initialised to zero.
    pub fn new(total_exchanges: usize, total_tokens: usize) -> Self {
        let len = total_exchanges * total_tokens;
        let balances = (0..len).map(|_| AtomicU64::new(0)).collect();
        Self {
            balances,
            total_tokens,
            total_exchanges,
            inventory: std::sync::Mutex::new(CategorizedInventory::new()),
        }
    }

    pub fn register_token(&self, id: u16, symbol: &str, mask: u16) {
        if let Ok(mut inv) = self.inventory.lock() {
            inv.register_token(id, symbol, mask);
        }
    }

    /// Delegated inventory lookups (acquire the Mutex briefly).
    pub fn get_category(&self, token_id: u16) -> u16 {
        self.inventory
            .lock()
            .ok()
            .and_then(|inv| inv.token_registry.get(&token_id).map(|t| t.category_mask))
            .unwrap_or(CAT_NONE)
    }

    pub fn get_id(&self, symbol: &str) -> Option<u16> {
        self.inventory
            .lock()
            .ok()
            .and_then(|inv| inv.symbol_to_id.get(&symbol.to_uppercase()).copied())
    }

    pub fn get_symbol(&self, id: u16) -> Option<String> {
        self.inventory
            .lock()
            .ok()
            .and_then(|inv| inv.token_registry.get(&id).map(|t| t.symbol.clone()))
    }

    /// Returns all token IDs whose category mask has the given bit(s) set.
    pub fn filter_by_category(&self, mask: u16) -> Vec<u16> {
        self.inventory
            .lock()
            .map(|inv| {
                inv.token_registry
                    .values()
                    .filter(|t| t.category_mask & mask != 0)
                    .map(|t| t.id)
                    .collect()
            })
            .unwrap_or_default()
    }

    // ---- atomic helpers ----

    #[inline]
    fn idx(&self, exchange_id: usize, token_id: usize) -> usize {
        exchange_id * self.total_tokens + token_id
    }

    /// Stores `balance` for `(exchange_id, token_id)` using a release store.
    /// The value is converted to fixed-point (truncated) before storing.
    pub fn update_balance_atomic(
        &self,
        exchange_id: usize,
        token_id: usize,
        balance: Decimal,
    ) {
        let fp = decimal_to_fp(balance);
        self.balances[self.idx(exchange_id, token_id)].store(fp, Ordering::Release);
    }

    /// Reads the balance for `(exchange_id, token_id)` with an acquire load
    /// and converts it back to `Decimal`.
    pub fn get_balance_atomic(&self, exchange_id: usize, token_id: usize) -> Decimal {
        let fp = self.balances[self.idx(exchange_id, token_id)].load(Ordering::Acquire);
        fp_to_decimal(fp)
    }

    /// Sums the balance of `token_id` across **all** exchanges.
    pub fn get_total_balance(&self, token_id: usize) -> Decimal {
        let mut total_fp: u64 = 0;
        for exchange_id in 0..self.total_exchanges {
            total_fp = total_fp.wrapping_add(
                self.balances[self.idx(exchange_id, token_id)].load(Ordering::Acquire),
            );
        }
        fp_to_decimal(total_fp)
    }

    /// Returns `min(available_balance, capital * max_pct)` for the given
    /// token on the given exchange.  Used by the execution engine to cap
    /// the safe trade size.
    pub fn compute_lot_size(
        &self,
        exchange_id: usize,
        token_id: usize,
        max_pct: Decimal,
        capital: Decimal,
    ) -> Decimal {
        let available = self.get_balance_atomic(exchange_id, token_id);
        let cap = capital * max_pct;
        if available < cap {
            available
        } else {
            cap
        }
    }

    /// Sums the balances of all tokens whose category mask has the given
    /// bit(s) set, on the specified exchange.
    pub fn get_category_exposure(&self, exchange_id: usize, category_mask: u16) -> Decimal {
        let matching = self.filter_by_category(category_mask);
        let mut total_fp: u64 = 0;
        for &tid in &matching {
            total_fp = total_fp.wrapping_add(
                self.balances[self.idx(exchange_id, tid as usize)]
                    .load(Ordering::Acquire),
            );
        }
        fp_to_decimal(total_fp)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rust_decimal_macros::dec;

    #[test]
    fn test_register_and_lookup_token() {
        let alloc = LocalCapitalAllocator::new(2, 16);
        alloc.register_token(0, "BTC", CAT_MAJOR);
        alloc.register_token(1, "ETH", CAT_MAJOR);
        alloc.register_token(2, "SOL", CAT_ALTCOIN);

        // Lookup by symbol (delegated through allocator)
        assert_eq!(alloc.get_id("BTC"), Some(0));
        assert_eq!(alloc.get_id("ETH"), Some(1));
        assert_eq!(alloc.get_id("SOL"), Some(2));
        assert_eq!(alloc.get_id("DOGE"), None);

        // Lookup by id
        assert_eq!(alloc.get_symbol(0), Some("BTC".to_string()));
        assert_eq!(alloc.get_symbol(1), Some("ETH".to_string()));

        // Category
        assert_eq!(alloc.get_category(0), CAT_MAJOR);
        assert_eq!(alloc.get_category(2), CAT_ALTCOIN);

        // filter_by_category
        let majors = alloc.filter_by_category(CAT_MAJOR);
        assert!(majors.contains(&0));
        assert!(majors.contains(&1));
        assert!(!majors.contains(&2));
    }

    #[test]
    fn test_atomic_balance_update_and_read() {
        let alloc = LocalCapitalAllocator::new(2, 8);
        let balance = dec!(3.141592);
        alloc.update_balance_atomic(0, 3, balance);

        // Reading back should give the truncated fixed-point value.
        // 3.141592 * 1_000_000 = 3_141_592  ->  Decimal(3.141592)
        let read = alloc.get_balance_atomic(0, 3);
        assert_eq!(read, dec!(3.141592));

        // A second exchange should still be zero
        assert_eq!(alloc.get_balance_atomic(1, 3), Decimal::ZERO);
    }

    #[test]
    fn test_total_balance_across_exchanges() {
        let alloc = LocalCapitalAllocator::new(3, 4);
        // Token 1 balances across exchanges
        alloc.update_balance_atomic(0, 1, dec!(10.5));
        alloc.update_balance_atomic(1, 1, dec!(20.25));
        alloc.update_balance_atomic(2, 1, dec!(0.75));

        let total = alloc.get_total_balance(1);
        assert_eq!(total, dec!(31.5));
    }

    #[test]
    fn test_lot_size_caps_at_max_pct() {
        let alloc = LocalCapitalAllocator::new(1, 4);
        // Available balance of 100 for token 0 on exchange 0
        alloc.update_balance_atomic(0, 0, dec!(100.0));

        // 50 % of capital 300 = 150, but only 100 available -> lot = 100
        let lot = alloc.compute_lot_size(0, 0, dec!(0.50), dec!(300.0));
        assert_eq!(lot, dec!(100.0));

        // 10 % of capital 300 = 30, which is < 100 available -> lot = 30
        let lot2 = alloc.compute_lot_size(0, 0, dec!(0.10), dec!(300.0));
        assert_eq!(lot2, dec!(30.0));

        // Edge: 0 % of capital = 0 -> lot = 0
        let lot3 = alloc.compute_lot_size(0, 0, dec!(0.00), dec!(1000.0));
        assert_eq!(lot3, Decimal::ZERO);
    }

    // -------------------------------------------------------------------
    // Fixed-point conversion consistency verification
    // -------------------------------------------------------------------

    /// Verify that decimal_to_fp → fp_to_decimal round-trip is lossless
    /// for all values with ≤ 6 decimal places (the FP scale).
    #[test]
    fn test_fp_round_trip_lossless() {
        let values = [
            dec!(0.000001), dec!(0.001), dec!(0.01), dec!(0.10),
            dec!(1.0), dec!(10.0), dec!(100.0), dec!(1000.0),
            dec!(10000.0), dec!(50000.0), dec!(100000.0), dec!(1000000.0),
            dec!(3.141592), dec!(0.000500), dec!(999999.999999),
        ];
        for val in &values {
            let fp = decimal_to_fp(*val);
            let recovered = fp_to_decimal(fp);
            assert_eq!(
                recovered, *val,
                "FP round-trip failed for {}: fp={}, recovered={}",
                val, fp, recovered,
            );
        }
    }

    /// Verify that values with > 6 decimal places are truncated (not rounded).
    #[test]
    fn test_fp_truncation_not_rounding() {
        // 0.0000009 → FP = 0 (truncated below 1 unit)
        let fp = decimal_to_fp(dec!(0.0000009));
        assert_eq!(fp, 0);

        // 0.0000015 → FP = 1 (truncated from 1.5)
        let fp2 = decimal_to_fp(dec!(0.0000015));
        assert_eq!(fp2, 1);

        // 100.0000009 → FP = 100_000_000 (9 truncated)
        let fp3 = decimal_to_fp(dec!(100.0000009));
        assert_eq!(fp3, 100_000_000);
    }

    /// Verify that the FP_SCALE constant is consistent with the conversion.
    #[test]
    fn test_fp_scale_consistency() {
        // 1.0 → FP = 1_000_000
        assert_eq!(decimal_to_fp(dec!(1.0)), 1_000_000);
        // 1_000_000 / 1_000_000 = 1.0
        assert_eq!(fp_to_decimal(1_000_000), dec!(1.0));
    }

    /// Verify get_total_balance sums correctly across exchanges using FP addition.
    #[test]
    fn test_total_balance_fp_summation() {
        let alloc = LocalCapitalAllocator::new(3, 2);
        // Give fractional balances that test FP precision
        alloc.update_balance_atomic(0, 1, dec!(33.333333));
        alloc.update_balance_atomic(1, 1, dec!(33.333333));
        alloc.update_balance_atomic(2, 1, dec!(33.333334));

        // Sum: 33.333333 + 33.333333 + 33.333334 = 100.000000
        let total = alloc.get_total_balance(1);
        assert_eq!(total, dec!(100.0));
    }
}