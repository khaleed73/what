//! Atomic Order Book — Lock-free fixed-size order book using atomic operations.
//!
//! This module provides a high-performance order book representation that uses
//! fixed-size arrays with atomic operations for lock-free concurrent access.
//! Designed for the hot path where every nanosecond counts.

use std::sync::atomic::{AtomicU64, Ordering};
use rust_decimal::prelude::ToPrimitive;
use rust_decimal::Decimal;

/// Maximum depth levels per side. Fixed at compile time for zero-allocation.
pub const MAX_BOOK_DEPTH: usize = 50;

/// Atomic representation of a single price level.
/// Uses u64 atomics with fixed-point encoding for lock-free reads.
/// Encoding: value_u64 = (value_f64 * 1_000_000_000) as u64 (9 decimal places)
///
/// A sequence-lock pattern prevents torn reads when reading both price and
/// quantity as a pair: `store()` increments `version` before and after the
/// writes, while `load()` retries if the version changed during the read.
pub struct AtomicLevel {
    price_fp: AtomicU64,    // Fixed-point price (9 decimals)
    quantity_fp: AtomicU64, // Fixed-point quantity (9 decimals)
    /// Monotonically increasing version counter for sequence-lock reads.
    /// Even = stable, odd = update in progress.
    version: AtomicU64,
}

const FP_SCALE_U64: u64 = 1_000_000_000;

impl Default for AtomicLevel {
    fn default() -> Self {
        Self::new()
    }
}

impl AtomicLevel {
    pub const fn new() -> Self {
        Self {
            price_fp: AtomicU64::new(0),
            quantity_fp: AtomicU64::new(0),
            version: AtomicU64::new(0),
        }
    }

    /// Converts a Decimal to fixed-point u64 (9 decimal places).
    /// NOTE: This goes through String allocation, which is slow (~100ns).
    /// For hot-path use, consider a pure-integer approach: extract the
    /// mantissa/coefficient directly from the Decimal's internal representation.
    #[inline]
    fn decimal_to_fp(d: Decimal) -> u64 {
        match d * Decimal::from(FP_SCALE_U64) {
            scaled if scaled >= Decimal::ZERO => {
                match scaled.to_u64() {
                    Some(fp) => fp,
                    None => {
                        tracing::warn!(value = %d, "atomic_orderbook decimal_to_fp: overflow, capping to u64::MAX");
                        u64::MAX
                    }
                }
            }
            _ => {
                tracing::warn!(value = %d, "atomic_orderbook decimal_to_fp: negative value, capping to 0");
                0
            }
        }
    }

    /// Converts a fixed-point u64 back to Decimal.
    #[inline]
    fn fp_to_decimal(fp: u64) -> Decimal {
        Decimal::from(fp) / Decimal::from(FP_SCALE_U64)
    }

    /// Stores a price/quantity pair atomically using a sequence-lock
    /// pattern to prevent torn reads in `load()`.
    pub fn store(&self, price: Decimal, quantity: Decimal) {
        let v = self.version.fetch_add(1, Ordering::Release);
        self.price_fp.store(Self::decimal_to_fp(price), Ordering::Release);
        self.quantity_fp.store(Self::decimal_to_fp(quantity), Ordering::Release);
        self.version.store(v + 2, Ordering::Release);
    }

    /// Loads the price atomically.
    pub fn load_price(&self) -> Decimal {
        Self::fp_to_decimal(self.price_fp.load(Ordering::Acquire))
    }

    /// Loads the quantity atomically.
    pub fn load_quantity(&self) -> Decimal {
        Self::fp_to_decimal(self.quantity_fp.load(Ordering::Acquire))
    }

    /// Loads both price and quantity using the sequence-lock pattern.
    /// Retries if a concurrent `store()` is in progress, guaranteeing
    /// a consistent (non-torn) pair.
    pub fn load(&self) -> (Decimal, Decimal) {
        loop {
            let v1 = self.version.load(Ordering::Acquire);
            if v1 & 1 != 0 {
                // Store in progress — spin briefly then retry.
                std::hint::spin_loop();
                continue;
            }
            let p = Self::fp_to_decimal(self.price_fp.load(Ordering::Acquire));
            let q = Self::fp_to_decimal(self.quantity_fp.load(Ordering::Acquire));
            let v2 = self.version.load(Ordering::Acquire);
            if v1 == v2 {
                return (p, q);
            }
            // Version changed — retry
        }
    }

    /// Zeros out this level (also bumps the version to invalidate stale reads).
    pub fn clear(&self) {
        let v = self.version.fetch_add(1, Ordering::Release);
        self.price_fp.store(0, Ordering::Release);
        self.quantity_fp.store(0, Ordering::Release);
        self.version.store(v + 2, Ordering::Release);
    }
}

/// Fixed-size atomic order book with lock-free reads.
///
/// Layout:
///   asks[0] = best (lowest) ask
///   bids[0] = best (highest) bid
///
/// The book does NOT self-sort. The caller (WS parser) is responsible
/// for maintaining sorted order when applying updates.
pub struct FixedOrderBook {
    pub asks: [AtomicLevel; MAX_BOOK_DEPTH],
    pub bids: [AtomicLevel; MAX_BOOK_DEPTH],
}

impl Default for FixedOrderBook {
    fn default() -> Self {
        Self::new()
    }
}

impl FixedOrderBook {
    pub const fn new() -> Self {
        Self {
            asks: [const { AtomicLevel::new() }; MAX_BOOK_DEPTH],
            bids: [const { AtomicLevel::new() }; MAX_BOOK_DEPTH],
        }
    }

    /// Returns the best (lowest) ask price and quantity.
    pub fn best_ask(&self) -> (Decimal, Decimal) {
        self.asks[0].load()
    }

    /// Returns the best (highest) bid price and quantity.
    pub fn best_bid(&self) -> (Decimal, Decimal) {
        self.bids[0].load()
    }

    /// Returns the mid-price (average of best bid and best ask).
    /// Returns None if either side has zero price.
    pub fn mid_price(&self) -> Option<Decimal> {
        let (bid, _) = self.best_bid();
        let (ask, _) = self.best_ask();
        if bid > Decimal::ZERO && ask > Decimal::ZERO {
            Some((bid + ask) / Decimal::TWO)
        } else {
            None
        }
    }

    /// Returns the spread (best ask - best bid) in absolute terms.
    pub fn spread(&self) -> Option<Decimal> {
        let (bid, _) = self.best_bid();
        let (ask, _) = self.best_ask();
        if bid > Decimal::ZERO && ask > Decimal::ZERO && ask > bid {
            Some(ask - bid)
        } else {
            None
        }
    }

    /// Returns the spread as a percentage of the mid-price.
    pub fn spread_bps(&self) -> Option<Decimal> {
        let (bid, _) = self.best_bid();
        let (ask, _) = self.best_ask();
        let mid = (bid + ask) / Decimal::TWO;
        if mid > Decimal::ZERO && ask > bid {
            Some(((ask - bid) / mid) * Decimal::from(10000u64))
        } else {
            None
        }
    }

    /// Clears all levels on both sides.
    pub fn clear_all(&self) {
        for level in &self.asks {
            level.clear();
        }
        for level in &self.bids {
            level.clear();
        }
    }

    /// Returns the total notional value available on the ask side up to N levels.
    pub fn ask_notional(&self, max_levels: usize) -> Decimal {
        let mut total = Decimal::ZERO;
        for i in 0..max_levels.min(MAX_BOOK_DEPTH) {
            let (price, qty) = self.asks[i].load();
            if price <= Decimal::ZERO { break; }
            total += price * qty;
        }
        total
    }

    /// Returns the total notional value available on the bid side up to N levels.
    pub fn bid_notional(&self, max_levels: usize) -> Decimal {
        let mut total = Decimal::ZERO;
        for i in 0..max_levels.min(MAX_BOOK_DEPTH) {
            let (price, qty) = self.bids[i].load();
            if price <= Decimal::ZERO { break; }
            total += price * qty;
        }
        total
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rust_decimal_macros::dec;

    #[test]
    fn test_atomic_level_store_load() {
        let level = AtomicLevel::new();
        level.store(dec!(50000.50), dec!(1.5));
        let (price, qty) = level.load();
        assert_eq!(price, dec!(50000.50));
        assert_eq!(qty, dec!(1.5));
    }

    #[test]
    fn test_atomic_level_clear() {
        let level = AtomicLevel::new();
        level.store(dec!(100.0), dec!(50.0));
        level.clear();
        assert_eq!(level.load_price(), Decimal::ZERO);
        assert_eq!(level.load_quantity(), Decimal::ZERO);
    }

    #[test]
    fn test_fixed_book_best_bid_ask() {
        let book = FixedOrderBook::new();
        book.bids[0].store(dec!(50000.0), dec!(1.0));
        book.bids[1].store(dec!(49990.0), dec!(2.0));
        book.asks[0].store(dec!(50010.0), dec!(0.5));
        book.asks[1].store(dec!(50020.0), dec!(1.0));

        let (bid, bid_qty) = book.best_bid();
        assert_eq!(bid, dec!(50000.0));
        assert_eq!(bid_qty, dec!(1.0));

        let (ask, ask_qty) = book.best_ask();
        assert_eq!(ask, dec!(50010.0));
        assert_eq!(ask_qty, dec!(0.5));
    }

    #[test]
    fn test_mid_price() {
        let book = FixedOrderBook::new();
        book.bids[0].store(dec!(50000.0), dec!(1.0));
        book.asks[0].store(dec!(50010.0), dec!(1.0));

        assert_eq!(book.mid_price(), Some(dec!(50005.0)));
    }

    #[test]
    fn test_mid_price_empty() {
        let book = FixedOrderBook::new();
        assert_eq!(book.mid_price(), None);
    }

    #[test]
    fn test_spread() {
        let book = FixedOrderBook::new();
        book.bids[0].store(dec!(50000.0), dec!(1.0));
        book.asks[0].store(dec!(50010.0), dec!(1.0));

        assert_eq!(book.spread(), Some(dec!(10.0)));
    }

    #[test]
    fn test_spread_bps() {
        let book = FixedOrderBook::new();
        book.bids[0].store(dec!(50000.0), dec!(1.0));
        book.asks[0].store(dec!(50010.0), dec!(1.0));

        // spread = 10, mid = 50005, bps = (10/50005) * 10000 ≈ 1.9998
        let bps = book.spread_bps().unwrap();
        assert!(bps > dec!(1.9) && bps < dec!(2.1));
    }

    #[test]
    fn test_clear_all() {
        let book = FixedOrderBook::new();
        book.bids[0].store(dec!(50000.0), dec!(1.0));
        book.asks[0].store(dec!(50010.0), dec!(1.0));
        book.clear_all();
        assert_eq!(book.best_bid().0, Decimal::ZERO);
        assert_eq!(book.best_ask().0, Decimal::ZERO);
    }

    #[test]
    fn test_ask_notional() {
        let book = FixedOrderBook::new();
        book.asks[0].store(dec!(50000.0), dec!(1.0));   // $50,000
        book.asks[1].store(dec!(50010.0), dec!(2.0));   // $100,020

        let notional = book.ask_notional(2);
        assert_eq!(notional, dec!(150020.0));
    }

    #[test]
    fn test_bid_notional() {
        let book = FixedOrderBook::new();
        book.bids[0].store(dec!(50000.0), dec!(1.0));   // $50,000
        book.bids[1].store(dec!(49990.0), dec!(1.0));   // $49,990

        let notional = book.bid_notional(2);
        assert_eq!(notional, dec!(99990.0));
    }

    #[test]
    fn test_fp_conversion_roundtrip() {
        let original = dec!(50000.123456789);
        let fp = AtomicLevel::decimal_to_fp(original);
        let recovered = AtomicLevel::fp_to_decimal(fp);
        // 9 decimal places of precision
        assert!((recovered - original).abs() < dec!(0.000000001));
    }
}