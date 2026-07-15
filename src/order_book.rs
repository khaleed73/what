//! L2 Order Book Depth System for HFT Arbitrage Bot
//!
//! Maintains full depth order books per (exchange, symbol) pair, parses
//! exchange-specific WebSocket messages, and exposes best-bid/ask and
//! depth-weighted average price queries used by the execution engine to
//! evaluate real fill quality before placing orders.

use dashmap::DashMap;
use futures_util::{SinkExt, StreamExt};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::time::{sleep, Duration};
use tokio_tungstenite::connect_async;
use tracing::{error, info, warn};

// ---------------------------------------------------------------------------
// Core data structures
// ---------------------------------------------------------------------------

/// Side of the order book.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Side {
    Bid,
    Ask,
}

/// A single price level in the order book.
#[derive(Debug, Clone, Copy)]
pub struct PriceLevel {
    pub price: Decimal,
    pub quantity: Decimal,
}

/// Full order book for a single (exchange, symbol) pair.
///
/// `bids` is ordered descending (best bid = highest price = last entry).
/// `asks` is ordered ascending (best ask = lowest price = first entry).
/// Both use `BTreeMap<Decimal, Decimal>` keyed by price, valued by quantity.
#[derive(Debug, Clone, Default)]
pub struct OrderBook {
    /// Price → quantity, sorted descending via `Reverse` wrapper at query
    /// time or by iterating `.rev()`.
    pub bids: BTreeMap<Decimal, Decimal>,
    /// Price → quantity, sorted ascending (natural BTreeMap order).
    pub asks: BTreeMap<Decimal, Decimal>,
    /// Monotonic sequence number from the exchange (if available) to detect
    /// out-of-order or stale updates.
    pub last_update_id: u64,
    /// Local timestamp of the last applied update (nanoseconds since epoch).
    pub last_update_ns: u64,
}

impl OrderBook {
    /// Create a new empty order book.
    pub fn new() -> Self {
        Self {
            bids: BTreeMap::new(),
            asks: BTreeMap::new(),
            last_update_id: 0,
            last_update_ns: 0,
        }
    }

    /// Apply an `OrderBookDelta` to this book.
    ///
    /// * If `is_snapshot` is true the book is **replaced** entirely.
    /// * Otherwise each level is upserted (zero-quantity entries are removed).
    ///
    /// For incremental updates, a price sanity check is applied: any new price
    /// that is > 10× or < 0.1× the current best price on the same side is
    /// rejected as a likely corrupted WebSocket message. Removals (zero-qty)
    /// and snapshots bypass this check.
    pub fn apply_delta(&mut self, delta: &OrderBookDelta) {
        if delta.is_snapshot {
            self.bids.clear();
            self.asks.clear();
        }

        // For incremental updates, get reference prices for sanity checks.
        let best_bid_ref = if !delta.is_snapshot {
            self.bids.last_key_value().map(|(p, _)| *p)
        } else {
            None
        };
        let best_ask_ref = if !delta.is_snapshot {
            self.asks.first_key_value().map(|(p, _)| *p)
        } else {
            None
        };

        for (price, qty) in &delta.bid_updates {
            if *qty <= Decimal::ZERO {
                self.bids.remove(price);
            } else if !Self::is_price_sane(*price, best_bid_ref) {
                warn!(
                    price = %price,
                    best_bid = %best_bid_ref.unwrap_or(Decimal::ZERO),
                    "Order book bid price failed sanity check (outside 0.1x–10x of best bid) — rejected"
                );
            } else {
                self.bids.insert(*price, *qty);
            }
        }

        for (price, qty) in &delta.ask_updates {
            if *qty <= Decimal::ZERO {
                self.asks.remove(price);
            } else if !Self::is_price_sane(*price, best_ask_ref) {
                warn!(
                    price = %price,
                    best_ask = %best_ask_ref.unwrap_or(Decimal::ZERO),
                    "Order book ask price failed sanity check (outside 0.1x–10x of best ask) — rejected"
                );
            } else {
                self.asks.insert(*price, *qty);
            }
        }

        if delta.last_update_id > self.last_update_id {
            self.last_update_id = delta.last_update_id;
        }
        self.last_update_ns = delta.last_update_ns;
    }

    /// Checks whether a price is within 0.1×–10× of a reference price.
    /// Returns `true` if the price is sane (or if there is no reference price
    /// to compare against, e.g. the book is empty).
    #[inline]
    fn is_price_sane(price: Decimal, reference: Option<Decimal>) -> bool {
        let ref_price = match reference {
            Some(r) if r > Decimal::ZERO => r,
            _ => return true, // No valid reference — allow everything
        };
        if price <= Decimal::ZERO {
            return true; // Zero-price removals are handled elsewhere
        }
        let upper = ref_price * Decimal::from(10u32);
        let lower = ref_price / Decimal::from(10u32);
        price >= lower && price <= upper
    }

    /// Trim the book to keep only the top `max_levels` on each side.
    /// This prevents unbounded memory growth on long-running processes.
    pub fn trim(&mut self, max_levels: usize) {
        while self.bids.len() > max_levels {
            // BTreeMap: smallest key first → remove from the worst (lowest) bid
            if let Some(worst_bid) = self.bids.keys().next().copied() {
                self.bids.remove(&worst_bid);
            } else {
                break;
            }
        }
        while self.asks.len() > max_levels {
            // BTreeMap: smallest key first, largest key last → worst ask = highest price
            if let Some(worst_ask) = self.asks.keys().next_back().copied() {
                self.asks.remove(&worst_ask);
            } else {
                break;
            }
        }
    }

    /// Return the number of bid levels.
    #[inline]
    pub fn bid_depth(&self) -> usize {
        self.bids.len()
    }

    /// Return the number of ask levels.
    #[inline]
    pub fn ask_depth(&self) -> usize {
        self.asks.len()
    }
}

// ---------------------------------------------------------------------------
// OrderBookDelta — the unit of change propagated through the system
// ---------------------------------------------------------------------------

/// Incremental update (or full snapshot replacement) for an order book.
#[derive(Debug, Clone, Default)]
pub struct OrderBookDelta {
    /// Price levels to insert / update / remove on the bid side.
    /// A quantity of zero means the level should be deleted.
    pub bid_updates: Vec<(Decimal, Decimal)>,
    /// Price levels to insert / update / remove on the ask side.
    pub ask_updates: Vec<(Decimal, Decimal)>,
    /// When true the delta represents a full snapshot and the book should be
    /// cleared before applying these levels.
    pub is_snapshot: bool,
    /// Sequence / update ID from the exchange.
    pub last_update_id: u64,
    /// Local timestamp (ns) when this delta was created.
    pub last_update_ns: u64,
}

impl OrderBookDelta {
    /// Convenience constructor for a snapshot delta.
    pub fn snapshot(
        bids: Vec<(Decimal, Decimal)>,
        asks: Vec<(Decimal, Decimal)>,
        update_id: u64,
    ) -> Self {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        Self {
            bid_updates: bids,
            ask_updates: asks,
            is_snapshot: true,
            last_update_id: update_id,
            last_update_ns: ts,
        }
    }

    /// Convenience constructor for an incremental delta.
    pub fn incremental(
        bids: Vec<(Decimal, Decimal)>,
        asks: Vec<(Decimal, Decimal)>,
        update_id: u64,
    ) -> Self {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        Self {
            bid_updates: bids,
            ask_updates: asks,
            is_snapshot: false,
            last_update_id: update_id,
            last_update_ns: ts,
        }
    }
}

// ---------------------------------------------------------------------------
// L2OrderBookManager — concurrent order book store
// ---------------------------------------------------------------------------

/// Thread-safe, lock-free (via `DashMap`) store of order books indexed by
/// `(exchange_id, symbol)`.
///
/// Internally a `DashMap<u16, DashMap<String, OrderBook>>` — the outer map
/// is keyed by exchange id, the inner map by normalized symbol (e.g.
/// `"BTCUSDT"`).  This allows an arbitrage scanner to shard work per
/// exchange without any `Mutex` contention.
pub struct L2OrderBookManager {
    /// exchange_id → (symbol → OrderBook)
    books: DashMap<u16, DashMap<String, OrderBook>>,
}

impl L2OrderBookManager {
    /// Create a new empty manager.
    pub fn new() -> Self {
        Self {
            books: DashMap::new(),
        }
    }

    /// Apply a delta to the book for `(exchange_id, symbol)`.
    ///
    /// If the book does not yet exist it is created automatically.
    pub fn apply_delta(
        &self,
        exchange_id: u16,
        symbol: &str,
        delta: &OrderBookDelta,
    ) {
        let symbol = symbol.to_uppercase().replace("-", "").replace("_", "").replace("/", "");

        // Ensure the inner map for this exchange exists.
        let inner = self
            .books
            .entry(exchange_id)
            .or_default();

        let mut book = inner.entry(symbol).or_default();
        book.apply_delta(delta);
    }

    /// Get a clone of the order book for `(exchange_id, symbol)`.
    /// Returns `None` if no data has been received for this pair yet.
    pub fn get_book(&self, exchange_id: u16, symbol: &str) -> Option<OrderBook> {
        let symbol = symbol.to_uppercase().replace("-", "").replace("_", "").replace("/", "");
        let inner = self.books.get(&exchange_id)?;
        let book = inner.get(&symbol)?;
        Some(book.clone())
    }

    /// Get the best bid/ask directly from the manager without cloning the
    /// entire book.  Returns `(best_bid_px, best_bid_qty, best_ask_px,
    /// best_ask_qty)` or `None` if the book is empty / missing.
    pub fn get_best_bid_ask(
        &self,
        exchange_id: u16,
        symbol: &str,
    ) -> Option<(Decimal, Decimal, Decimal, Decimal)> {
        let book = self.get_book(exchange_id, symbol)?;
        get_best_bid_ask(&book)
    }

    /// Return the current number of exchanges that have at least one book.
    pub fn exchange_count(&self) -> usize {
        self.books.len()
    }

    /// Return the total number of (exchange, symbol) books stored.
    pub fn total_books(&self) -> usize {
        self.books.iter().map(|inner| inner.value().len()).sum()
    }

    /// Get a reference to the underlying `DashMap` for advanced access
    /// patterns (e.g. iterating all books on an exchange).
    pub fn inner(&self) -> &DashMap<u16, DashMap<String, OrderBook>> {
        &self.books
    }

    /// Remove all books for a given exchange.  Useful when reconnecting.
    pub fn clear_exchange(&self, exchange_id: u16) {
        self.books.remove(&exchange_id);
    }
}

impl Default for L2OrderBookManager {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Query helpers
// ---------------------------------------------------------------------------

/// Return `(best_bid_price, best_bid_qty, best_ask_price, best_ask_qty)` from
/// the given `OrderBook`.
///
/// * Best bid = highest bid price (last entry in the BTreeMap).
/// * Best ask = lowest ask price  (first entry in the BTreeMap).
pub fn get_best_bid_ask(book: &OrderBook) -> Option<(Decimal, Decimal, Decimal, Decimal)> {
    let best_bid = book.bids.last_key_value()?;
    let best_ask = book.asks.first_key_value()?;
    Some((
        *best_bid.0,
        *best_bid.1,
        *best_ask.0,
        *best_ask.1,
    ))
}

/// Walk the book from the best price on `side`, accumulating quantity × price
/// until `max_usd` worth of notional is reached.  Returns the **volume-weighted
/// average price** (VWAP) for that depth slice.
///
/// This is used by the execution engine to determine the real fill price
/// for a given order size, accounting for slippage through multiple levels.
///
/// # Algorithm
///
/// ```text
/// cum_usd = 0
/// cum_qty = 0
/// for each level (price, qty):
///     fill_usd = min(qty * price, max_usd - cum_usd)
///     fill_qty = fill_usd / price
///     cum_usd += fill_usd
///     cum_qty += fill_qty
///     if cum_usd >= max_usd: break
/// return cum_usd > 0 ? cum_usd / cum_qty : Decimal::ZERO
/// ```
pub fn get_depth_value(book: &OrderBook, side: Side, max_usd: Decimal) -> Decimal {
    if max_usd <= Decimal::ZERO {
        return Decimal::ZERO;
    }

    let levels: Vec<(Decimal, Decimal)> = match side {
        Side::Bid => book.bids.iter().rev().map(|(&p, &q)| (p, q)).collect(),
        Side::Ask => book.asks.iter().map(|(&p, &q)| (p, q)).collect(),
    };

    let mut cum_usd = Decimal::ZERO;
    let mut cum_qty = Decimal::ZERO;

    for (price, qty) in &levels {
        if *price <= Decimal::ZERO {
            continue;
        }
        let level_usd = qty * price;
        let remaining = max_usd - cum_usd;
        if remaining <= Decimal::ZERO {
            break;
        }
        let fill_usd = if level_usd <= remaining {
            level_usd
        } else {
            remaining
        };
        let fill_qty = fill_usd / *price;
        cum_usd += fill_usd;
        cum_qty += fill_qty;
    }

    if cum_qty > Decimal::ZERO {
        cum_usd / cum_qty
    } else {
        Decimal::ZERO
    }
}

// ---------------------------------------------------------------------------
// Exchange-specific subscription message builder
// ---------------------------------------------------------------------------

/// Build the L2 order book WebSocket subscription message for the given
/// exchange.
///
/// `symbols` should use the canonical form (e.g. `"BTCUSDT"`).  This function
/// maps to each exchange's required format.  Returns `None` for exchanges
/// that use a different subscription mechanism (e.g. KuCoin REST token).
///
/// # Exchange ID mapping
///
/// | ID | Exchange    |
/// |----|-------------|
/// | 0  | Binance     |
/// | 1  | Bybit       |
/// | 2  | OKX         |
/// | 3  | GateIO      |
/// | 4  | KuCoin      |
/// | 5  | Bitfinex    |
/// | 6  | Bitget      |
/// | 7  | BitMEX      |
/// | 8  | Coinbase    |
/// | 9  | HTX         |
/// | 10 | Kraken      |
/// | 11 | LBank       |
/// | 12 | Bitstamp    |
/// | 13 | Deribit     |
/// | 14 | Delta       |
/// | 15 | MEXC        |
/// | 16 | Ibank       |
pub fn build_orderbook_subscribe(exchange_id: u16, symbols: &[String]) -> Option<String> {
    // Fall back to BTCUSDT if the caller provides an empty list.
    let syms: Vec<&str> = if symbols.is_empty() {
        vec!["BTCUSDT"]
    } else {
        symbols.iter().map(|s| s.as_str()).collect()
    };

    match exchange_id {
        // 0 — Binance: lowercase symbol + @depth20@100ms
        0 => {
            let params: Vec<String> = syms
                .iter()
                .map(|s| format!("{}@depth20@100ms", s.to_lowercase()))
                .collect();
            Some(format!(
                r#"{{"method":"subscribe","params":{:?}}}"#,
                params
            ))
        }

        // 1 — Bybit: orderbook.100.SYMBOL
        1 => {
            let args: Vec<String> = syms
                .iter()
                .map(|s| format!("orderbook.100.{}", s))
                .collect();
            Some(format!(
                r#"{{"op":"subscribe","args":{:?}}}"#,
                args
            ))
        }

        // 2 — OKX: books5 channel with hyphenated instId
        2 => {
            let args: Vec<serde_json::Value> = syms
                .iter()
                .map(|s| {
                    let inst_id = symbol_to_okx(s);
                    serde_json::json!({
                        "channel": "books5",
                        "instId": inst_id
                    })
                })
                .collect();
            Some(format!(
                r#"{{"op":"subscribe","args":{}}}"#,
                serde_json::to_string(&args).unwrap_or_default()
            ))
        }

        // 3 — GateIO: spot.order_book with underscore separator, live timestamp
        3 => {
            let ts = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0);
            let payload: Vec<String> = syms
                .iter()
                .map(|s| symbol_to_gateio(s))
                .collect();
            Some(format!(
                r#"{{"time":{},"channel":"spot.order_book","event":"subscribe","payload":{:?}}}"#,
                ts, payload
            ))
        }

        // 4 — KuCoin: handled via REST-obtained WS token, not direct subscribe
        4 => None,

        // 5 — Bitfinex: book channel, t-prefixed symbol
        5 => {
            // Bitfinex sends one subscribe message per symbol.
            // We build a JSON array of individual subscribe objects.
            let subs: Vec<serde_json::Value> = syms
                .iter()
                .map(|s| {
                    let sym = symbol_to_bitfinex(s);
                    serde_json::json!({
                        "event": "subscribe",
                        "channel": "book",
                        "symbol": sym,
                        "prec": "P0",
                        "len": "25"
                    })
                })
                .collect();
            Some(serde_json::to_string(&subs).unwrap_or_default())
        }

        // 6 — Bitget: fallback to tickers channel (no true L2 WS)
        6 => {
            let args: Vec<String> = syms
                .iter()
                .map(|s| format!("tickers.{}", s))
                .collect();
            Some(format!(
                r#"{{"op":"subscribe","args":{:?}}}"#,
                args
            ))
        }

        // 7 — BitMEX: orderBookL2_25:SYMBOL
        7 => {
            let args: Vec<String> = syms
                .iter()
                .map(|s| format!("orderBookL2_25:{}", symbol_to_bitmex(s)))
                .collect();
            Some(format!(
                r#"{{"op":"subscribe","args":{:?}}}"#,
                args
            ))
        }

        // 8 — Coinbase: level2 channel with hyphenated product_id
        8 => {
            let product_ids: Vec<String> = syms
                .iter()
                .map(|s| symbol_to_coinbase(s))
                .collect();
            let msg = serde_json::json!({
                "type": "subscribe",
                "product_ids": product_ids,
                "channels": ["level2"]
            });
            Some(serde_json::to_string(&msg).unwrap_or_default())
        }

        // 9 — HTX: market.depth.SYMBOL
        9 => {
            // HTX subscribes one symbol at a time. Build array of messages.
            let subs: Vec<serde_json::Value> = syms
                .iter()
                .map(|s| {
                    serde_json::json!({
                        "sub": format!("market.depth.{}", s),
                        "id": "depth_sub"
                    })
                })
                .collect();
            Some(serde_json::to_string(&subs).unwrap_or_default())
        }

        // 10 — Kraken: book subscription, XBT/USDT pairing
        10 => {
            let pairs: Vec<String> = syms
                .iter()
                .map(|s| symbol_to_kraken(s))
                .collect();
            let msg = serde_json::json!({
                "event": "subscribe",
                "pair": pairs,
                "subscription": { "name": "book" }
            });
            Some(serde_json::to_string(&msg).unwrap_or_default())
        }

        // 11 — LBank: depth subscription
        11 => {
            let pairs: Vec<&str> = syms.to_vec();
            let msg = serde_json::json!({
                "action": "subscribe",
                "subscribe": "depth",
                "pair": pairs
            });
            Some(serde_json::to_string(&msg).unwrap_or_default())
        }

        // 12 — Bitstamp: diff_order_book channel, lowercase
        12 => {
            let subs: Vec<serde_json::Value> = syms
                .iter()
                .map(|s| {
                    serde_json::json!({
                        "event": "bts:subscribe",
                        "data": {
                            "channel": format!("diff_order_book_{}", s.to_lowercase())
                        }
                    })
                })
                .collect();
            Some(serde_json::to_string(&subs).unwrap_or_default())
        }

        // 13 — Deribit: JSON-RPC book channel, 100ms
        13 => {
            let channels: Vec<String> = syms
                .iter()
                .map(|s| format!("book.{}.100ms", s))
                .collect();
            let msg = serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "public/subscribe",
                "params": {
                    "channels": channels
                }
            });
            Some(serde_json::to_string(&msg).unwrap_or_default())
        }

        // 14 — Delta: v2/orderbook channel
        14 => {
            let symbols_vec: Vec<&str> = syms.to_vec();
            let msg = serde_json::json!({
                "type": "subscribe",
                "payload": {
                    "channel": "v2/orderbook",
                    "symbols": symbols_vec
                }
            });
            Some(serde_json::to_string(&msg).unwrap_or_default())
        }

        // 15 — MEXC: Binance-compatible format
        15 => {
            let params: Vec<String> = syms
                .iter()
                .map(|s| format!("{}@depth20@100ms", s.to_lowercase()))
                .collect();
            Some(format!(
                r#"{{"method":"subscribe","params":{:?}}}"#,
                params
            ))
        }

        // 16 — Ibank: book:SYMBOL
        16 => {
            let args: Vec<String> = syms
                .iter()
                .map(|s| format!("book:{}", s))
                .collect();
            Some(format!(
                r#"{{"op":"subscribe","args":{:?}}}"#,
                args
            ))
        }

        // Unknown — Binance-compatible fallback
        _ => {
            let params: Vec<String> = syms
                .iter()
                .map(|s| format!("{}@depth20@100ms", s.to_lowercase()))
                .collect();
            Some(format!(
                r#"{{"method":"subscribe","params":{:?}}}"#,
                params
            ))
        }
    }
}

// ---------------------------------------------------------------------------
// Symbol format converters
// ---------------------------------------------------------------------------

/// `"BTCUSDT"` → `"BTC-USDT"` (inserts hyphen before the last 3 chars, or
/// before the last quote-stable suffix if recognisable).
fn symbol_to_okx(sym: &str) -> String {
    if sym.len() > 3 {
        let sep = find_quote_separator(sym);
        format!("{}-{}", &sym[..sep], &sym[sep..])
    } else {
        sym.to_string()
    }
}

/// `"BTCUSDT"` → `"BTC_USDT"`
fn symbol_to_gateio(sym: &str) -> String {
    if sym.len() > 3 {
        let sep = find_quote_separator(sym);
        format!("{}_{}", &sym[..sep], &sym[sep..])
    } else {
        sym.to_string()
    }
}

/// `"BTCUSDT"` → `"tBTCUSD"`
fn symbol_to_bitfinex(sym: &str) -> String {
    if sym.len() > 3 {
        let sep = find_quote_separator(sym);
        format!("t{}_{}", &sym[..sep], &sym[sep..])
    } else {
        format!("t{}", sym)
    }
}

/// `"BTCUSDT"` → `"XBTUSDT"` (BTC → XBT for BitMEX)
fn symbol_to_bitmex(sym: &str) -> String {
    sym.replace("BTCUSDT", "XBTUSDT")
        .replace("BTC", "XBT")
}

/// `"BTCUSDT"` → `"BTC-USDT"`
fn symbol_to_coinbase(sym: &str) -> String {
    symbol_to_okx(sym)
}

/// `"BTCUSDT"` → `"XBT/USDT"`
fn symbol_to_kraken(sym: &str) -> String {
    if sym.len() > 3 {
        let sep = find_quote_separator(sym);
        let base = &sym[..sep];
        let quote = &sym[sep..];
        let base = if base == "BTC" { "XBT" } else { base };
        format!("{}/{}", base, quote)
    } else {
        sym.to_string()
    }
}

/// Known stable quote currencies used to find the base/quote boundary.
const QUOTE_SUFFIXES: &[&str] = &[
    "USDT", "USDC", "USD", "BUSD", "TUSD", "DAI", "EUR", "GBP", "BTC", "ETH", "BNB",
];

/// Find the index where the quote currency starts inside a concatenated symbol
/// like `"BTCUSDT"` → returns `3`.
fn find_quote_separator(sym: &str) -> usize {
    let upper = sym.to_uppercase();
    for suffix in QUOTE_SUFFIXES {
        if upper.ends_with(suffix) && upper.len() > suffix.len() {
            return upper.len() - suffix.len();
        }
    }
    // Fallback: assume last 3 or 4 characters are the quote.
    if sym.len() > 4 {
        sym.len() - 4
    } else if sym.len() > 3 {
        sym.len() - 3
    } else {
        1
    }
}

// ---------------------------------------------------------------------------
// Exchange-specific order book message parsers
// ---------------------------------------------------------------------------

// --- Binance depth ---

/// Binance partial book depth response.
#[derive(Deserialize)]
struct BinanceDepth {
    /// Event type — we only care about messages containing `"b"` and `"a"`.
    #[allow(dead_code)]
    e: Option<String>,
    /// Symbol, e.g. `"BTCUSDT"`.
    #[allow(dead_code)]
    s: Option<String>,
    /// Last update ID.
    #[serde(default)]
    lastUpdateId: u64,
    /// Bids: `[["price", "qty"], ...]`
    b: Vec<Vec<serde_json::Value>>,
    /// Asks: `[["price", "qty"], ...]`
    a: Vec<Vec<serde_json::Value>>,
}

// --- OKX books5 ---

#[derive(Deserialize)]
struct OkxBookResp {
    #[allow(dead_code)]
    arg: Option<OkxArg>,
    /// `"snapshot"` or `"update"`.
    action: Option<String>,
    data: Vec<OkxBookData>,
}

#[derive(Deserialize)]
struct OkxArg {
    #[allow(dead_code)]
    channel: Option<String>,
    #[allow(dead_code)]
    instId: Option<String>,
}

#[derive(Deserialize)]
struct OkxBookData {
    bids: Vec<Vec<serde_json::Value>>,
    asks: Vec<Vec<serde_json::Value>>,
    #[serde(default)]
    seqId: Option<String>,
}

// --- Bybit orderbook ---

#[derive(Deserialize)]
struct BybitBookResp {
    #[allow(dead_code)]
    topic: Option<String>,
    /// `"snapshot"` or `"delta"`.
    r#type: Option<String>,
    data: Option<BybitBookData>,
}

#[derive(Deserialize)]
struct BybitBookData {
    #[allow(dead_code)]
    s: Option<String>,
    /// Bids: `[["price", "size"], ...]`
    b: Vec<Vec<serde_json::Value>>,
    /// Asks: `[["price", "size"], ...]`
    a: Vec<Vec<serde_json::Value>>,
    #[serde(default)]
    u: u64,
    #[serde(default)]
    seq: u64,
}

// --- BitMEX orderBookL2 ---

#[derive(Deserialize)]
struct BitmexBookResp {
    #[allow(dead_code)]
    table: Option<String>,
    /// `"partial"`, `"insert"`, `"update"`, or `"delete"`.
    action: Option<String>,
    data: Vec<BitmexBookLevel>,
}

#[derive(Deserialize)]
struct BitmexBookLevel {
    #[allow(dead_code)]
    symbol: Option<String>,
    #[allow(dead_code)]
    id: Option<u64>,
    side: Option<String>,
    #[serde(default)]
    size: u32,
    price: Option<serde_json::Value>,
}

// --- Coinbase level2 ---

#[derive(Deserialize)]
struct CoinbaseL2 {
    r#type: Option<String>,
    #[allow(dead_code)]
    product_id: Option<String>,
    /// For snapshots: `[["price", "size"], ...]`
    bids: Option<Vec<Vec<serde_json::Value>>>,
    asks: Option<Vec<Vec<serde_json::Value>>>,
    /// For l2_update: `[["side", "price", "size"], ...]`
    changes: Option<Vec<Vec<serde_json::Value>>>,
}

// --- GateIO order_book ---

#[derive(Deserialize)]
struct GateIOBookResp {
    #[allow(dead_code)]
    time: Option<u64>,
    #[allow(dead_code)]
    channel: Option<String>,
    #[allow(dead_code)]
    event: Option<String>,
    /// Only present in update messages.
    result: Option<GateIOBookResult>,
}

#[derive(Deserialize)]
struct GateIOBookResult {
    #[allow(dead_code)]
    s: Option<String>,
    bids: Option<Vec<Vec<serde_json::Value>>>,
    asks: Option<Vec<Vec<serde_json::Value>>>,
    #[serde(default)]
    lastUpdateId: u64,
}

// --- Bitfinex book ---

/// Bitfinex sends arrays like `[chan_id, [[price, count, amount], ...]]`.
/// We parse this manually since it's not standard JSON object format.

// --- HTX depth ---

#[derive(Deserialize)]
struct HtxDepthResp {
    #[allow(dead_code)]
    ch: Option<String>,
    tick: Option<HtxDepthTick>,
}

#[derive(Deserialize)]
struct HtxDepthTick {
    bids: Option<Vec<Vec<serde_json::Value>>>,
    asks: Option<Vec<Vec<serde_json::Value>>>,
    #[serde(default)]
    id: u64,
}

// --- Kraken book ---

/// Kraken sends arrays: `[chan_id, { "as": [...], "bs": [...] }]`.
/// We parse this manually.

// --- LBank depth ---

#[derive(Deserialize)]
struct LBankDepthResp {
    #[allow(dead_code)]
    pair: Option<String>,
    #[allow(dead_code)]
    r#type: Option<String>,
    data: Option<LBankDepthData>,
}

#[derive(Deserialize)]
struct LBankDepthData {
    bids: Option<Vec<Vec<serde_json::Value>>>,
    asks: Option<Vec<Vec<serde_json::Value>>>,
    #[serde(default)]
    timestamp: u64,
}

// --- Bitstamp diff_order_book ---

#[derive(Deserialize)]
struct BitstampBookResp {
    #[allow(dead_code)]
    event: Option<String>,
    #[allow(dead_code)]
    channel: Option<String>,
    data: Option<BitstampBookData>,
}

#[derive(Deserialize)]
struct BitstampBookData {
    bids: Option<Vec<Vec<serde_json::Value>>>,
    asks: Option<Vec<Vec<serde_json::Value>>>,
    #[serde(default)]
    timestamp: u64,
}

// --- Deribit book ---

#[derive(Deserialize)]
struct DeribitBookResp {
    /// JSON-RPC method or notification params.
    params: Option<DeribitBookParams>,
}

#[derive(Deserialize)]
struct DeribitBookParams {
    /// Channel name, e.g. `"book.BTC-PERP.100ms"`.
    #[allow(dead_code)]
    channel: Option<String>,
    data: Option<DeribitBookData>,
}

#[derive(Deserialize)]
struct DeribitBookData {
    bids: Vec<Vec<serde_json::Value>>,
    asks: Vec<Vec<serde_json::Value>>,
    #[serde(default)]
    id: u64,
}

// ---------------------------------------------------------------------------
// parse_orderbook_update — main dispatcher
// ---------------------------------------------------------------------------

/// Parse an exchange-specific raw WebSocket text message into an
/// `OrderBookDelta`.  Returns `None` if the message is not a recognised
/// order book update (e.g. a subscription confirmation, heartbeat, or
/// malformed JSON).
///
/// # Supported exchanges (full parser)
///
/// * **Binance (0)** — `depthUpdate` / partial book depth
/// * **OKX (2)** — `books5` snapshot / update
/// * **Bybit (1)** — `orderbook.100` snapshot / delta
/// * **BitMEX (7)** — `orderBookL2_25` partial / insert / update / delete
/// * **Coinbase (8)** — `level2` snapshot / l2_update
/// * **GateIO (3)** — `spot.order_book` update
/// * **HTX (9)** — `market.depth` push
/// * **LBank (11)** — depth push
/// * **Bitstamp (12)** — `diff_order_book` update
/// * **Deribit (13)** — `book.*` subscription notification
///
/// # Partially supported (best-effort JSON extraction)
///
/// * **Bitfinex (5)** — array-based protocol parsed manually
/// * **Kraken (10)** — array-based protocol parsed manually
/// * **Bitget (6)** — ticker fallback, not true L2
/// * **Delta (14)** — generic JSON extraction
/// * **MEXC (15)** — Binance-compatible format, reuses Binance parser
/// * **Ibank (16)** — generic JSON extraction
///
/// # Generic fallback
///
/// Any exchange not listed above falls through to a generic parser that
/// looks for top-level `"bids"` and `"asks"` arrays (the most common
/// convention).
pub fn parse_orderbook_update(
    exchange_id: u16,
    _symbol: &str,
    raw: &str,
) -> Option<OrderBookDelta> {
    // Strip leading/trailing whitespace
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }

    match exchange_id {
        0 | 15 => parse_binance_depth(raw),
        1 => parse_bybit_book(raw),
        2 => parse_okx_book(raw),
        3 => parse_gateio_book(raw),
        5 => parse_bitfinex_book(raw),
        6 => parse_bitget_ticker_book(raw),
        7 => parse_bitmex_book(raw),
        8 => parse_coinbase_l2(raw),
        9 => parse_htx_depth(raw),
        10 => parse_kraken_book(raw),
        11 => parse_lbank_depth(raw),
        12 => parse_bitstamp_book(raw),
        13 => parse_deribit_book(raw),
        14 | 16 => parse_generic_book(raw),
        _ => parse_generic_book(raw),
    }
}

// --- Binance / MEXC (identical format) ---

fn parse_binance_depth(raw: &str) -> Option<OrderBookDelta> {
    let v: serde_json::Value = serde_json::from_str(raw).ok()?;

    // Binance may wrap in {"result": ...} for combined streams.
    let inner = v
        .get("result")
        .unwrap_or(&v)
        .get("data")
        .unwrap_or(v.get("result").unwrap_or(&v));

    // For combined streams: {"stream":"...", "data": {...}}
    let data = v.get("data").unwrap_or(inner);

    let bids_arr = data.get("b")?.as_array()?;
    let asks_arr = data.get("a")?.as_array()?;

    let update_id = data
        .get("lastUpdateId")
        .or_else(|| data.get("u"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    let is_snapshot = data
        .get("e")
        .and_then(|e| e.as_str())
        .map(|e| e == "depthUpdate")
        .unwrap_or(true); // partial book depth snapshots have no "e"

    let bid_updates = parse_price_qty_pairs(bids_arr);
    let ask_updates = parse_price_qty_pairs(asks_arr);

    if bid_updates.is_empty() && ask_updates.is_empty() {
        return None;
    }

    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);

    Some(OrderBookDelta {
        bid_updates,
        ask_updates,
        is_snapshot,
        last_update_id: update_id,
        last_update_ns: ts,
    })
}

// --- Bybit ---

fn parse_bybit_book(raw: &str) -> Option<OrderBookDelta> {
    let v: serde_json::Value = serde_json::from_str(raw).ok()?;

    // Ignore subscription confirmations
    if v.get("op").is_some() {
        return None;
    }
    // Ignore pong messages
    if v.get("ret_msg").is_some_and(|m| m.as_str() == Some("pong")) {
        return None;
    }

    let data = v.get("data")?;

    let bids_arr = data.get("b")?.as_array()?;
    let asks_arr = data.get("a")?.as_array()?;

    let update_id = data
        .get("u")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    let is_snapshot = v
        .get("type")
        .and_then(|t| t.as_str())
        .map(|t| t == "snapshot")
        .unwrap_or(false);

    let bid_updates = parse_price_qty_pairs(bids_arr);
    let ask_updates = parse_price_qty_pairs(asks_arr);

    if bid_updates.is_empty() && ask_updates.is_empty() {
        return None;
    }

    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);

    Some(OrderBookDelta {
        bid_updates,
        ask_updates,
        is_snapshot,
        last_update_id: update_id,
        last_update_ns: ts,
    })
}

// --- OKX ---

fn parse_okx_book(raw: &str) -> Option<OrderBookDelta> {
    let v: serde_json::Value = serde_json::from_str(raw).ok()?;

    // Ignore subscribe confirmations {"event":"subscribe",...}
    if v.get("event").is_some() {
        return None;
    }

    let data_arr = v.get("data")?.as_array()?;
    if data_arr.is_empty() {
        return None;
    }

    let first = &data_arr[0];
    let bids_arr = first.get("bids")?.as_array()?;
    let asks_arr = first.get("asks")?.as_array()?;

    let update_id = first
        .get("seqId")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0);

    let is_snapshot = v
        .get("action")
        .and_then(|a| a.as_str())
        .map(|a| a == "snapshot")
        .unwrap_or(false);

    // OKX books5: each level is [price, qty, ...]
    let bid_updates = parse_price_qty_pairs(bids_arr);
    let ask_updates = parse_price_qty_pairs(asks_arr);

    if bid_updates.is_empty() && ask_updates.is_empty() {
        return None;
    }

    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);

    Some(OrderBookDelta {
        bid_updates,
        ask_updates,
        is_snapshot,
        last_update_id: update_id,
        last_update_ns: ts,
    })
}

// --- GateIO ---

fn parse_gateio_book(raw: &str) -> Option<OrderBookDelta> {
    let v: serde_json::Value = serde_json::from_str(raw).ok()?;

    // Ignore subscribe confirmations
    if v.get("event").and_then(|e| e.as_str()) == Some("subscribe") {
        return None;
    }

    let result = v.get("result")?;

    let bids_arr = result.get("bids")?.as_array()?;
    let asks_arr = result.get("asks")?.as_array()?;

    let update_id = result
        .get("lastUpdateId")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    let bid_updates = parse_price_qty_pairs(bids_arr);
    let ask_updates = parse_price_qty_pairs(asks_arr);

    if bid_updates.is_empty() && ask_updates.is_empty() {
        return None;
    }

    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);

    Some(OrderBookDelta {
        bid_updates,
        ask_updates,
        is_snapshot: false,
        last_update_id: update_id,
        last_update_ns: ts,
    })
}

// --- Bitfinex (array-based protocol) ---
// Bitfinex book updates arrive as: [chan_id, [[price, count, amount], ...]]
// or [chan_id, price, count, amount] for single-level updates.
// count=0 means the level should be removed.
// amount > 0 → bid, amount < 0 → ask (absolute value is the quantity).

fn parse_bitfinex_book(raw: &str) -> Option<OrderBookDelta> {
    let v: serde_json::Value = serde_json::from_str(raw).ok()?;

    // Must be an array
    let arr = v.as_array()?;

    // We expect either:
    //   [chan_id, [[px, cnt, amt], ...]]  — snapshot / multi-level
    //   [chan_id, px, cnt, amt]            — single-level update
    //   {"event": "...", ...}              — subscription confirmation (skip)
    if arr.is_empty() {
        return None;
    }

    // Skip subscription event objects
    if arr[0].is_object() {
        return None;
    }

    // First element is channel ID (number) — skip it.
    let mut bid_updates = Vec::new();
    let mut ask_updates = Vec::new();
    let mut is_snapshot = false;
    let update_id: u64 = 0;

    if arr.len() >= 4 {
        // Single-level update: [chan_id, price, count, amount]
        let price = parse_decimal_value(&arr[1])?;
        let count = arr[2].as_i64().unwrap_or(0);
        let amount = parse_decimal_value(&arr[3]).unwrap_or(Decimal::ZERO);

        if count == 0 {
            // Remove level — insert with zero quantity
            if amount > Decimal::ZERO {
                bid_updates.push((price, Decimal::ZERO));
            } else {
                ask_updates.push((price, Decimal::ZERO));
            }
        } else {
            if amount > Decimal::ZERO {
                bid_updates.push((price, amount));
            } else {
                ask_updates.push((price, amount.abs()));
            }
        }
    } else if arr.len() >= 2 {
        // Multi-level: [chan_id, [[px, cnt, amt], ...]]
        let levels = arr[1].as_array()?;
        is_snapshot = levels.len() > 1; // Heuristic

        for level in levels {
            let level_arr = level.as_array()?;
            if level_arr.len() < 3 {
                continue;
            }
            let price = parse_decimal_value(&level_arr[0]).unwrap_or(Decimal::ZERO);
            let count = level_arr[1].as_i64().unwrap_or(0);
            let amount = parse_decimal_value(&level_arr[2]).unwrap_or(Decimal::ZERO);

            if price <= Decimal::ZERO {
                continue;
            }

            if count == 0 {
                if amount > Decimal::ZERO {
                    bid_updates.push((price, Decimal::ZERO));
                } else {
                    ask_updates.push((price, Decimal::ZERO));
                }
            } else {
                if amount > Decimal::ZERO {
                    bid_updates.push((price, amount));
                } else {
                    ask_updates.push((price, amount.abs()));
                }
            }
        }
    }

    if bid_updates.is_empty() && ask_updates.is_empty() {
        return None;
    }

    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);

    Some(OrderBookDelta {
        bid_updates,
        ask_updates,
        is_snapshot,
        last_update_id: update_id,
        last_update_ns: ts,
    })
}

// --- Bitget (ticker fallback — no true L2 book) ---
// Ticker message: {"op":"subscribe",...} (skip) or
// {"tickers": [{"symbol":"BTCUSDT","bid1":"50000","ask1":"50001",
//   "bidSz1":"1.5","askSz1":"0.5",...}]}
// We extract bid1/ask1 as single-level book updates.

fn parse_bitget_ticker_book(raw: &str) -> Option<OrderBookDelta> {
    let v: serde_json::Value = serde_json::from_str(raw).ok()?;

    // Skip subscription confirmations
    if v.get("op").is_some() {
        return None;
    }

    let tickers = match v.get("data").and_then(|d| d.as_array()) {
        Some(arr) => arr,
        None => v.get("tickers").and_then(|t| t.as_array())?,
    };

    if tickers.is_empty() {
        return None;
    }

    let t = &tickers[0];

    let bid_price = t
        .get("bid1")
        .or_else(|| t.get("bidPr"))
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<Decimal>().ok())
        .unwrap_or(Decimal::ZERO);

    let ask_price = t
        .get("ask1")
        .or_else(|| t.get("askPr"))
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<Decimal>().ok())
        .unwrap_or(Decimal::ZERO);

    let bid_qty = t
        .get("bidSz1")
        .or_else(|| t.get("bidSz"))
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<Decimal>().ok())
        .unwrap_or(Decimal::ZERO);

    let ask_qty = t
        .get("askSz1")
        .or_else(|| t.get("askSz"))
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<Decimal>().ok())
        .unwrap_or(Decimal::ZERO);

    if bid_price <= Decimal::ZERO && ask_price <= Decimal::ZERO {
        return None;
    }

    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);

    Some(OrderBookDelta {
        bid_updates: if bid_price > Decimal::ZERO {
            vec![(bid_price, bid_qty)]
        } else {
            vec![]
        },
        ask_updates: if ask_price > Decimal::ZERO {
            vec![(ask_price, ask_qty)]
        } else {
            vec![]
        },
        is_snapshot: true,
        last_update_id: 0,
        last_update_ns: ts,
    })
}

// --- BitMEX ---

fn parse_bitmex_book(raw: &str) -> Option<OrderBookDelta> {
    let v: serde_json::Value = serde_json::from_str(raw).ok()?;

    // Skip subscription confirmations: {"success":true,...}
    if v.get("success").is_some() {
        return None;
    }

    let table = v.get("table")?.as_str()?;
    if !table.starts_with("orderBookL2") {
        return None;
    }

    let action = v.get("action")?.as_str()?;
    let data_arr = v.get("data")?.as_array()?;

    let is_snapshot = action == "partial";

    let mut bid_updates = Vec::new();
    let mut ask_updates = Vec::new();
    let mut max_id: u64 = 0;

    for level in data_arr {
        let side = level.get("side").and_then(|s| s.as_str()).unwrap_or("");
        let price_str = level.get("price").and_then(|p| p.as_str()).unwrap_or("0");
        let size = level
            .get("size")
            .and_then(|s| s.as_u64())
            .unwrap_or(0);

        let id = level
            .get("id")
            .and_then(|i| i.as_u64())
            .unwrap_or(0);
        if id > max_id {
            max_id = id;
        }

        let price: Decimal = price_str.parse().unwrap_or(Decimal::ZERO);
        if price <= Decimal::ZERO {
            continue;
        }

        match action {
            "delete" => {
                let qty = Decimal::ZERO;
                match side {
                    "Buy" => bid_updates.push((price, qty)),
                    "Sell" => ask_updates.push((price, qty)),
                    _ => {}
                }
            }
            _ => {
                // "partial", "insert", "update" — all upsert the level
                let qty = Decimal::from(size);
                match side {
                    "Buy" => bid_updates.push((price, qty)),
                    "Sell" => ask_updates.push((price, qty)),
                    _ => {}
                }
            }
        }
    }

    if bid_updates.is_empty() && ask_updates.is_empty() {
        return None;
    }

    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);

    Some(OrderBookDelta {
        bid_updates,
        ask_updates,
        is_snapshot,
        last_update_id: max_id,
        last_update_ns: ts,
    })
}

// --- Coinbase L2 ---

fn parse_coinbase_l2(raw: &str) -> Option<OrderBookDelta> {
    let v: serde_json::Value = serde_json::from_str(raw).ok()?;

    let msg_type = v.get("type")?.as_str()?;

    match msg_type {
        "snapshot" => {
            let bids_arr = v.get("bids")?.as_array()?;
            let asks_arr = v.get("asks")?.as_array()?;

            let bid_updates = parse_price_qty_pairs(bids_arr);
            let ask_updates = parse_price_qty_pairs(asks_arr);

            if bid_updates.is_empty() && ask_updates.is_empty() {
                return None;
            }

            let ts = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0);

            Some(OrderBookDelta {
                bid_updates,
                ask_updates,
                is_snapshot: true,
                last_update_id: 0,
                last_update_ns: ts,
            })
        }
        "l2_update" => {
            let changes = v.get("changes")?.as_array()?;

            let mut bid_updates = Vec::new();
            let mut ask_updates = Vec::new();

            for change in changes {
                let change_arr = change.as_array()?;
                if change_arr.len() < 3 {
                    continue;
                }
                let side_str = change_arr[0].as_str().unwrap_or("");
                let price: Decimal = change_arr[1]
                    .as_str()
                    .unwrap_or("0")
                    .parse()
                    .unwrap_or(Decimal::ZERO);
                let qty: Decimal = change_arr[2]
                    .as_str()
                    .unwrap_or("0")
                    .parse()
                    .unwrap_or(Decimal::ZERO);

                if price <= Decimal::ZERO {
                    continue;
                }

                match side_str {
                    "buy" => bid_updates.push((price, qty)),
                    "sell" => ask_updates.push((price, qty)),
                    _ => {}
                }
            }

            if bid_updates.is_empty() && ask_updates.is_empty() {
                return None;
            }

            let ts = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0);

            Some(OrderBookDelta {
                bid_updates,
                ask_updates,
                is_snapshot: false,
                last_update_id: 0,
                last_update_ns: ts,
            })
        }
        _ => None,
    }
}

// --- HTX ---

fn parse_htx_depth(raw: &str) -> Option<OrderBookDelta> {
    let v: serde_json::Value = serde_json::from_str(raw).ok()?;

    // Skip subscription confirmation: {"status":"ok","subbed":"...",...}
    if v.get("status").is_some() {
        return None;
    }

    let tick = v.get("tick")?;

    let bids_arr = tick.get("bids")?.as_array()?;
    let asks_arr = tick.get("asks")?.as_array()?;

    let update_id = tick
        .get("id")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    let bid_updates = parse_price_qty_pairs(bids_arr);
    let ask_updates = parse_price_qty_pairs(asks_arr);

    if bid_updates.is_empty() && ask_updates.is_empty() {
        return None;
    }

    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);

    Some(OrderBookDelta {
        bid_updates,
        ask_updates,
        is_snapshot: false,
        last_update_id: update_id,
        last_update_ns: ts,
    })
}

// --- Kraken (array-based protocol) ---
// Snapshot: [chan_id, {"as": [["50001.00000","1.000","1.000"],...], "bs": [...]}, "book-100"]
// Update:   [chan_id, {"a": [["50001.00000","1.000","1.000"]], "b": [...]}, "book-100"]

fn parse_kraken_book(raw: &str) -> Option<OrderBookDelta> {
    let v: serde_json::Value = serde_json::from_str(raw).ok()?;

    let arr = v.as_array()?;
    if arr.len() < 2 {
        return None;
    }

    // Skip subscription confirmations: {"event":"subscribe",...}
    if arr[0].is_object() {
        return None;
    }

    let book_data = &arr[1];

    // Kraken book levels: [price, qty, timestamp]
    // "as"/"bs" for snapshot, "a"/"b" for update
    let mut bid_updates = Vec::new();
    let mut ask_updates = Vec::new();
    let mut is_snapshot = false;

    // Snapshot keys: "as" (asks snapshot), "bs" (bids snapshot)
    if let Some(asks) = book_data.get("as").and_then(|v| v.as_array()) {
        is_snapshot = true;
        ask_updates = parse_price_qty_pairs_3(asks);
    }
    if let Some(bids) = book_data.get("bs").and_then(|v| v.as_array()) {
        is_snapshot = true;
        bid_updates = parse_price_qty_pairs_3(bids);
    }

    // Update keys: "a" (asks update), "b" (bids update)
    if let Some(asks) = book_data.get("a").and_then(|v| v.as_array()) {
        ask_updates = parse_price_qty_pairs_3(asks);
    }
    if let Some(bids) = book_data.get("b").and_then(|v| v.as_array()) {
        bid_updates = parse_price_qty_pairs_3(bids);
    }

    if bid_updates.is_empty() && ask_updates.is_empty() {
        return None;
    }

    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);

    Some(OrderBookDelta {
        bid_updates,
        ask_updates,
        is_snapshot,
        last_update_id: 0,
        last_update_ns: ts,
    })
}

// --- LBank ---

fn parse_lbank_depth(raw: &str) -> Option<OrderBookDelta> {
    let v: serde_json::Value = serde_json::from_str(raw).ok()?;

    // Skip subscription confirmations / pong
    if v.get("type").and_then(|t| t.as_str()) == Some("subscribe") {
        return None;
    }

    let data = v.get("data")?;

    let bids_arr = data.get("bids")?.as_array()?;
    let asks_arr = data.get("asks")?.as_array()?;

    let update_id = data
        .get("timestamp")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    let bid_updates = parse_price_qty_pairs(bids_arr);
    let ask_updates = parse_price_qty_pairs(asks_arr);

    if bid_updates.is_empty() && ask_updates.is_empty() {
        return None;
    }

    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);

    Some(OrderBookDelta {
        bid_updates,
        ask_updates,
        is_snapshot: false,
        last_update_id: update_id,
        last_update_ns: ts,
    })
}

// --- Bitstamp ---

fn parse_bitstamp_book(raw: &str) -> Option<OrderBookDelta> {
    let v: serde_json::Value = serde_json::from_str(raw).ok()?;

    // Skip subscription confirmations: {"event":"bts:subscription_succeeded",...}
    if let Some(event) = v.get("event").and_then(|e| e.as_str()) {
        if event.contains("subscription") {
            return None;
        }
    }

    let data = v.get("data")?;

    let bids_arr = data.get("bids")?.as_array()?;
    let asks_arr = data.get("asks")?.as_array()?;

    let update_id = data
        .get("timestamp")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    let bid_updates = parse_price_qty_pairs(bids_arr);
    let ask_updates = parse_price_qty_pairs(asks_arr);

    if bid_updates.is_empty() && ask_updates.is_empty() {
        return None;
    }

    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);

    Some(OrderBookDelta {
        bid_updates,
        ask_updates,
        is_snapshot: false,
        last_update_id: update_id,
        last_update_ns: ts,
    })
}

// --- Deribit ---

fn parse_deribit_book(raw: &str) -> Option<OrderBookDelta> {
    let v: serde_json::Value = serde_json::from_str(raw).ok()?;

    // Skip subscription confirmations: {"jsonrpc":"2.0","result":...}
    if v.get("result").is_some() {
        return None;
    }

    let params = v.get("params")?;
    let data = params.get("data")?;

    let bids_arr = data.get("bids")?.as_array()?;
    let asks_arr = data.get("asks")?.as_array()?;

    let update_id = data
        .get("id")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    // Deribit levels: [price, qty, ...]
    let bid_updates = parse_price_qty_pairs(bids_arr);
    let ask_updates = parse_price_qty_pairs(asks_arr);

    if bid_updates.is_empty() && ask_updates.is_empty() {
        return None;
    }

    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);

    Some(OrderBookDelta {
        bid_updates,
        ask_updates,
        is_snapshot: false,
        last_update_id: update_id,
        last_update_ns: ts,
    })
}

// --- Generic fallback ---
// Looks for top-level "bids"/"asks" arrays (2-element: [price, qty]).

fn parse_generic_book(raw: &str) -> Option<OrderBookDelta> {
    let v: serde_json::Value = serde_json::from_str(raw).ok()?;

    // Try to find bids and asks at the top level or one level deep
    let bids_arr = v
        .get("bids")
        .or_else(|| v.get("data").and_then(|d| d.get("bids")))
        .or_else(|| v.get("result").and_then(|r| r.get("bids")))
        .and_then(|b| b.as_array())?;

    let asks_arr = v
        .get("asks")
        .or_else(|| v.get("data").and_then(|d| d.get("asks")))
        .or_else(|| v.get("result").and_then(|r| r.get("asks")))
        .and_then(|a| a.as_array())?;

    let update_id = v
        .get("id")
        .or_else(|| v.get("data").and_then(|d| d.get("id")))
        .or_else(|| v.get("lastUpdateId"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    let bid_updates = parse_price_qty_pairs(bids_arr);
    let ask_updates = parse_price_qty_pairs(asks_arr);

    if bid_updates.is_empty() && ask_updates.is_empty() {
        return None;
    }

    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);

    Some(OrderBookDelta {
        bid_updates,
        ask_updates,
        is_snapshot: false,
        last_update_id: update_id,
        last_update_ns: ts,
    })
}

// ---------------------------------------------------------------------------
// Helper parsers
// ---------------------------------------------------------------------------

/// Parse an array of `[price, qty]` pairs into a Vec of `(Decimal, Decimal)`.
/// Handles both string and numeric JSON values for price and quantity.
fn parse_price_qty_pairs(arr: &[serde_json::Value]) -> Vec<(Decimal, Decimal)> {
    let mut out = Vec::with_capacity(arr.len());
    for pair in arr {
        if let Some(pair_arr) = pair.as_array() {
            if pair_arr.len() >= 2 {
                let price = parse_decimal_value(&pair_arr[0]);
                let qty = parse_decimal_value(&pair_arr[1]);
                if let (Some(p), Some(q)) = (price, qty) {
                    if p > Decimal::ZERO {
                        out.push((p, q));
                    }
                }
            }
        }
    }
    out
}

/// Parse an array of `[price, qty, _]` 3-element pairs (Kraken format).
fn parse_price_qty_pairs_3(arr: &[serde_json::Value]) -> Vec<(Decimal, Decimal)> {
    let mut out = Vec::with_capacity(arr.len());
    for pair in arr {
        if let Some(pair_arr) = pair.as_array() {
            if pair_arr.len() >= 2 {
                let price = parse_decimal_value(&pair_arr[0]);
                let qty = parse_decimal_value(&pair_arr[1]);
                if let (Some(p), Some(q)) = (price, qty) {
                    if p > Decimal::ZERO {
                        out.push((p, q));
                    }
                }
            }
        }
    }
    out
}

/// Parse a `serde_json::Value` into a `Decimal`.
/// Handles both string (`"50000.50"`) and number (`50000.50`) forms.
fn parse_decimal_value(v: &serde_json::Value) -> Option<Decimal> {
    if let Some(s) = v.as_str() {
        s.parse::<Decimal>().ok()
    } else if let Some(n) = v.as_f64() {
        Decimal::from_f64_retain(n)
    } else if let Some(n) = v.as_i64() {
        Some(Decimal::from(n))
    } else { v.as_u64().map(Decimal::from) }
}

// ---------------------------------------------------------------------------
// L2OrderBookListener — WebSocket consumer for order book data
// ---------------------------------------------------------------------------

/// WebSocket listener that connects to a single exchange, subscribes to L2
/// order book channels, parses incoming messages into `OrderBookDelta`s, and
/// applies them to the shared `L2OrderBookManager`.
///
/// Mirrors the architecture of `LowLatencyWsListener` in `datafeed.rs`:
/// * Exponential back-off reconnection (1 s → 2 s → 4 s → … → 30 s cap).
/// * Close frame terminates the listener.
/// * `symbol_watch` provides dynamic symbol lists (re-subscribe on reconnect).
pub struct L2OrderBookListener {
    /// Exchange ID (0–16).
    pub exchange_id: u16,
    /// WebSocket URL for this exchange.
    pub wss_url: String,
    /// Shared order book store.
    pub manager: Arc<L2OrderBookManager>,
    /// Watch channel for the latest symbol list (re-subscribe on reconnect).
    pub symbol_watch: tokio::sync::watch::Receiver<Vec<String>>,
    /// How many message-parse failures before logging a warning (debounce).
    parse_error_count: std::sync::atomic::AtomicU32,
    /// Total deltas successfully applied (diagnostic counter).
    pub applied_delta_count: std::sync::atomic::AtomicU64,
}

impl L2OrderBookListener {
    /// Create a new listener.
    pub fn new(
        exchange_id: u16,
        wss_url: String,
        manager: Arc<L2OrderBookManager>,
        symbol_watch: tokio::sync::watch::Receiver<Vec<String>>,
    ) -> Self {
        Self {
            exchange_id,
            wss_url,
            manager,
            symbol_watch,
            parse_error_count: std::sync::atomic::AtomicU32::new(0),
            applied_delta_count: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Connect to the WebSocket and stream order book updates into the
    /// shared `L2OrderBookManager`.  Reconnects with exponential back-off on
    /// failure.  Returns when the server sends a close frame.
    pub async fn start_streaming(&self) {
        let ex = self.exchange_id;
        info!(
            exchange_id = ex,
            url = %self.wss_url,
            "starting L2 order book WS listener"
        );

        let mut consecutive_failures: u32 = 0;
        const BASE_DELAY_SECS: u64 = 1;
        const MAX_DELAY_SECS: u64 = 30;

        loop {
            match connect_async(&self.wss_url).await {
                Ok((ws_stream, _response)) => {
                    consecutive_failures = 0;
                    info!(exchange_id = ex, "L2 order book websocket connected");

                    let (mut write, mut read) = ws_stream.split();

                    // Send subscription message
                    let current_symbols = self.symbol_watch.borrow().clone();
                    if let Some(sub_msg) =
                        build_orderbook_subscribe(self.exchange_id, &current_symbols)
                    {
                        if let Err(e) = write
                            .send(tokio_tungstenite::tungstenite::Message::Text(
                                sub_msg,
                            ))
                            .await
                        {
                            error!(
                                exchange_id = ex,
                                error = %e,
                                "failed to send L2 order book WS subscribe message"
                            );
                            break;
                        }
                        info!(
                            exchange_id = ex,
                            "sent L2 order book subscription for {} symbols",
                            current_symbols.len()
                        );
                    } else {
                        info!(
                            exchange_id = ex,
                            "exchange does not require direct WS subscription (e.g. KuCoin)"
                        );
                    }

                    // Process incoming messages
                    while let Some(msg) = read.next().await {
                        match msg {
                            Ok(tokio_tungstenite::tungstenite::Message::Text(text)) => {
                                // DESIGN NOTE: Each L2 WS listener is intended to
                                // subscribe to a single symbol.  We take `.first()`
                                // from the watch channel as the target symbol for
                                // `apply_delta`.  The exchange-specific parsers inside
                                // `parse_orderbook_update` also extract the symbol from
                                // the message payload itself, but `OrderBookDelta` does
                                // not carry a symbol field — so the outer symbol is used
                                // as the book key.  For multi-symbol book support, a
                                // separate listener task per symbol (or a muxed parser)
                                // would be needed.
                                let symbol = self
                                    .symbol_watch
                                    .borrow()
                                    .first()
                                    .cloned()
                                    .unwrap_or_else(|| "UNKNOWN".to_string());

                                if let Some(delta) = parse_orderbook_update(
                                    self.exchange_id,
                                    &symbol,
                                    &text,
                                ) {
                                    self.manager
                                        .apply_delta(self.exchange_id, &symbol, &delta);

                                    self.applied_delta_count
                                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                } else {
                                    let errs = self
                                        .parse_error_count
                                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                    // Log every 1000th parse failure to avoid log spam.
                                    if (errs + 1).is_multiple_of(1000) {
                                        warn!(
                                            exchange_id = ex,
                                            parse_errors = errs + 1,
                                            "L2 order book: accumulated parse errors (non-book messages)"
                                        );
                                    }
                                }
                            }
                            Ok(tokio_tungstenite::tungstenite::Message::Close(_)) => {
                                info!(
                                    exchange_id = ex,
                                    "L2 order book websocket close received, stopping"
                                );
                                return;
                            }
                            Ok(_) => {
                                // Ignore Ping / Pong / Binary
                            }
                            Err(e) => {
                                error!(
                                    exchange_id = ex,
                                    error = %e,
                                    "L2 order book websocket read error"
                                );
                                break;
                            }
                        }
                    }

                    warn!(
                        exchange_id = ex,
                        "L2 order book WS stream ended, reconnecting"
                    );
                }
                Err(e) => {
                    consecutive_failures += 1;
                    let delay_secs = (BASE_DELAY_SECS
                        << consecutive_failures.saturating_sub(1))
                        .min(MAX_DELAY_SECS);
                    error!(
                        exchange_id = ex,
                        error = %e,
                        consecutive_failures,
                        delay_secs,
                        "L2 order book websocket connect failed, reconnecting with exponential backoff"
                    );
                    sleep(Duration::from_secs(delay_secs)).await;
                    continue;
                }
            }

            // Stream ended (not a connect failure) — backoff before retry
            consecutive_failures += 1;
            let delay_secs = (BASE_DELAY_SECS
                << consecutive_failures.saturating_sub(1))
                .min(MAX_DELAY_SECS);
            warn!(
                exchange_id = ex,
                consecutive_failures,
                delay_secs,
                "L2 order book: reconnecting with exponential backoff"
            );
            sleep(Duration::from_secs(delay_secs)).await;
        }
    }
}

// ---------------------------------------------------------------------------
// Spawner
// ---------------------------------------------------------------------------

/// Spawn one tokio task per exchange for L2 order book depth streaming.
/// Returns the vector of `JoinHandle`s so the caller can await or abort them.
///
/// Each listener connects to the exchange's WebSocket, subscribes to L2 depth
/// channels, and writes parsed deltas into the shared `manager`.
///
/// `symbol_watch` follows the same pattern as `spawn_feed_workers` in
/// `datafeed.rs`: the coin finder pushes updated symbol lists and each
/// listener re-subscribes on reconnect with the latest list.
pub fn spawn_ob_workers(
    manager: Arc<L2OrderBookManager>,
    exchanges: Vec<(u16, String)>,
    symbol_watch: tokio::sync::watch::Receiver<Vec<String>>,
) -> Vec<tokio::task::JoinHandle<()>> {
    let mut handles = Vec::with_capacity(exchanges.len());

    for (exchange_id, wss_url) in exchanges {
        let listener =
            L2OrderBookListener::new(exchange_id, wss_url, Arc::clone(&manager), symbol_watch.clone());
        let handle = tokio::spawn(async move {
            listener.start_streaming().await;
        });
        handles.push(handle);
    }

    handles
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rust_decimal_macros::dec;

    #[test]
    fn test_order_book_apply_snapshot() {
        let mut book = OrderBook::new();
        let delta = OrderBookDelta::snapshot(
            vec![(dec!(50000), dec!(1.5)), (dec!(49999), dec!(2.0))],
            vec![(dec!(50001), dec!(0.5)), (dec!(50002), dec!(1.0))],
            100,
        );
        book.apply_delta(&delta);

        assert_eq!(book.bid_depth(), 2);
        assert_eq!(book.ask_depth(), 2);
        assert_eq!(book.last_update_id, 100);

        let (bb_px, bb_q, ba_px, ba_q) = get_best_bid_ask(&book).unwrap();
        assert_eq!(bb_px, dec!(50000));
        assert_eq!(bb_q, dec!(1.5));
        assert_eq!(ba_px, dec!(50001));
        assert_eq!(ba_q, dec!(0.5));
    }

    #[test]
    fn test_order_book_apply_incremental() {
        let mut book = OrderBook::new();

        // Start with a snapshot
        let snap = OrderBookDelta::snapshot(
            vec![(dec!(50000), dec!(1.0)), (dec!(49999), dec!(2.0))],
            vec![(dec!(50001), dec!(1.0)), (dec!(50002), dec!(2.0))],
            100,
        );
        book.apply_delta(&snap);

        // Incremental update: add a new bid level and remove an ask level
        let inc = OrderBookDelta::incremental(
            vec![(dec!(50001), dec!(0.5))],
            vec![(dec!(50002), dec!(0.0))],
            101,
        );
        book.apply_delta(&inc);

        assert_eq!(book.bid_depth(), 3);
        assert_eq!(book.ask_depth(), 1); // 50002 removed

        let (bb_px, _, ba_px, _) = get_best_bid_ask(&book).unwrap();
        assert_eq!(bb_px, dec!(50001)); // New best bid
        assert_eq!(ba_px, dec!(50001)); // Best ask unchanged
    }

    #[test]
    fn test_order_book_zero_qty_removes_level() {
        let mut book = OrderBook::new();
        let snap = OrderBookDelta::snapshot(
            vec![(dec!(50000), dec!(1.0))],
            vec![(dec!(50001), dec!(1.0))],
            1,
        );
        book.apply_delta(&snap);

        // Remove bid level by setting qty to zero
        let delta = OrderBookDelta::incremental(vec![(dec!(50000), dec!(0))], vec![], 2);
        book.apply_delta(&delta);

        assert_eq!(book.bid_depth(), 0);
        assert!(get_best_bid_ask(&book).is_none());
    }

    #[test]
    fn test_get_depth_value_bids() {
        let mut book = OrderBook::new();
        let snap = OrderBookDelta::snapshot(
            vec![
                (dec!(50000), dec!(1.0)),  // $50,000 total at this level
                (dec!(49999), dec!(1.0)),  // $49,999 total at this level
                (dec!(49998), dec!(1.0)),  // $49,998 total at this level
            ],
            vec![(dec!(50001), dec!(1.0))],
            1,
        );
        book.apply_delta(&snap);

        // Buy $100,000 worth of BTC — need to walk into second level
        let vwap = get_depth_value(&book, Side::Bid, dec!(100000));
        // Expected: (50000*1 + 49999*1) / (1+1) = 99999/2 = 49999.5
        assert!((vwap - dec!(49999.5)).abs() < dec!(0.001));
    }

    #[test]
    fn test_get_depth_value_single_level() {
        let mut book = OrderBook::new();
        let snap = OrderBookDelta::snapshot(
            vec![(dec!(50000), dec!(10.0))],
            vec![(dec!(50001), dec!(10.0))],
            1,
        );
        book.apply_delta(&snap);

        // Buy $25,000 — fits entirely in the first level
        let vwap = get_depth_value(&book, Side::Bid, dec!(25000));
        assert_eq!(vwap, dec!(50000));

        // Buy $0 — return zero
        let vwap_zero = get_depth_value(&book, Side::Bid, dec!(0));
        assert_eq!(vwap_zero, Decimal::ZERO);
    }

    #[test]
    fn test_get_depth_value_exceeds_book() {
        let mut book = OrderBook::new();
        let snap = OrderBookDelta::snapshot(
            vec![(dec!(50000), dec!(1.0))],
            vec![(dec!(50001), dec!(1.0))],
            1,
        );
        book.apply_delta(&snap);

        // Request more than available ($100,000 but only $50,000 in book)
        let vwap = get_depth_value(&book, Side::Bid, dec!(100000));
        assert_eq!(vwap, dec!(50000)); // Only one level available
    }

    #[test]
    fn test_get_depth_value_asks() {
        let mut book = OrderBook::new();
        let snap = OrderBookDelta::snapshot(
            vec![(dec!(50000), dec!(1.0))],
            vec![
                (dec!(50001), dec!(1.0)), // $50,001
                (dec!(50002), dec!(1.0)), // $50,002
            ],
            1,
        );
        book.apply_delta(&snap);

        // Sell $100,000 — walk into second ask level
        let vwap = get_depth_value(&book, Side::Ask, dec!(100000));
        assert!((vwap - dec!(50001.5)).abs() < dec!(0.001));
    }

    #[test]
    fn test_l2_order_book_manager_apply_and_get() {
        let manager = L2OrderBookManager::new();

        let delta = OrderBookDelta::snapshot(
            vec![(dec!(50000), dec!(1.5))],
            vec![(dec!(50001), dec!(0.5))],
            42,
        );
        manager.apply_delta(0, "BTCUSDT", &delta);

        let result = manager.get_best_bid_ask(0, "BTCUSDT");
        assert!(result.is_some());
        let (bb_px, bb_q, ba_px, ba_q) = result.unwrap();
        assert_eq!(bb_px, dec!(50000));
        assert_eq!(bb_q, dec!(1.5));
        assert_eq!(ba_px, dec!(50001));
        assert_eq!(ba_q, dec!(0.5));
    }

    #[test]
    fn test_l2_order_book_manager_symbol_normalisation() {
        let manager = L2OrderBookManager::new();

        let delta = OrderBookDelta::snapshot(
            vec![(dec!(50000), dec!(1.0))],
            vec![(dec!(50001), dec!(1.0))],
            1,
        );
        // Store with hyphenated format
        manager.apply_delta(0, "BTC-USDT", &delta);

        // Retrieve with different normalisations
        assert!(manager.get_book(0, "BTCUSDT").is_some());
        assert!(manager.get_book(0, "btcusdt").is_some());
        assert!(manager.get_book(0, "BTC_USDT").is_some());
        assert!(manager.get_book(0, "BTC/USDT").is_some());
    }

    #[test]
    fn test_l2_order_book_manager_missing_book() {
        let manager = L2OrderBookManager::new();
        assert!(manager.get_best_bid_ask(0, "NONEXISTENT").is_none());
    }

    #[test]
    fn test_build_orderbook_subscribe_binance() {
        let msg = build_orderbook_subscribe(0, &["BTCUSDT".to_string()]);
        assert!(msg.is_some());
        let msg = msg.unwrap();
        assert!(msg.contains("depth20@100ms"));
        assert!(msg.contains("btcusdt"));
    }

    #[test]
    fn test_build_orderbook_subscribe_kucoin_is_none() {
        let msg = build_orderbook_subscribe(4, &["BTCUSDT".to_string()]);
        assert!(msg.is_none());
    }

    #[test]
    fn test_build_orderbook_subscribe_bybit() {
        let msg = build_orderbook_subscribe(1, &["BTCUSDT".to_string()]);
        assert!(msg.is_some());
        let msg = msg.unwrap();
        assert!(msg.contains("orderbook.100.BTCUSDT"));
    }

    #[test]
    fn test_build_orderbook_subscribe_okx() {
        let msg = build_orderbook_subscribe(2, &["BTCUSDT".to_string()]);
        assert!(msg.is_some());
        let msg = msg.unwrap();
        assert!(msg.contains("books5"));
        assert!(msg.contains("BTC-USDT"));
    }

    #[test]
    fn test_build_orderbook_subscribe_bitmex() {
        let msg = build_orderbook_subscribe(7, &["BTCUSDT".to_string()]);
        assert!(msg.is_some());
        let msg = msg.unwrap();
        assert!(msg.contains("orderBookL2_25:XBTUSDT"));
    }

    #[test]
    fn test_build_orderbook_subscribe_coinbase() {
        let msg = build_orderbook_subscribe(8, &["BTCUSDT".to_string()]);
        assert!(msg.is_some());
        let msg = msg.unwrap();
        assert!(msg.contains("level2"));
        assert!(msg.contains("BTC-USDT"));
    }

    #[test]
    fn test_build_orderbook_subscribe_gateio() {
        let msg = build_orderbook_subscribe(3, &["BTCUSDT".to_string()]);
        assert!(msg.is_some());
        let msg = msg.unwrap();
        assert!(msg.contains("spot.order_book"));
        assert!(msg.contains("BTC_USDT"));
        assert!(msg.contains("\"time\":"));
    }

    #[test]
    fn test_build_orderbook_subscribe_bitfinex() {
        let msg = build_orderbook_subscribe(5, &["BTCUSDT".to_string()]);
        assert!(msg.is_some());
        let msg = msg.unwrap();
        assert!(msg.contains("book"));
        assert!(msg.contains("tBTC_USD"));
        assert!(msg.contains("P0"));
    }

    #[test]
    fn test_build_orderbook_subscribe_htx() {
        let msg = build_orderbook_subscribe(9, &["BTCUSDT".to_string()]);
        assert!(msg.is_some());
        let msg = msg.unwrap();
        assert!(msg.contains("market.depth.BTCUSDT"));
    }

    #[test]
    fn test_build_orderbook_subscribe_kraken() {
        let msg = build_orderbook_subscribe(10, &["BTCUSDT".to_string()]);
        assert!(msg.is_some());
        let msg = msg.unwrap();
        assert!(msg.contains("XBT/USDT"));
        assert!(msg.contains("book"));
    }

    #[test]
    fn test_build_orderbook_subscribe_lbank() {
        let msg = build_orderbook_subscribe(11, &["BTCUSDT".to_string()]);
        assert!(msg.is_some());
        let msg = msg.unwrap();
        assert!(msg.contains("depth"));
        assert!(msg.contains("BTCUSDT"));
    }

    #[test]
    fn test_build_orderbook_subscribe_bitstamp() {
        let msg = build_orderbook_subscribe(12, &["BTCUSDT".to_string()]);
        assert!(msg.is_some());
        let msg = msg.unwrap();
        assert!(msg.contains("diff_order_book_btcusdt"));
    }

    #[test]
    fn test_build_orderbook_subscribe_deribit() {
        let msg = build_orderbook_subscribe(13, &["BTCUSDT".to_string()]);
        assert!(msg.is_some());
        let msg = msg.unwrap();
        assert!(msg.contains("book.BTCUSDT.100ms"));
        assert!(msg.contains("public/subscribe"));
    }

    #[test]
    fn test_build_orderbook_subscribe_delta() {
        let msg = build_orderbook_subscribe(14, &["BTCUSDT".to_string()]);
        assert!(msg.is_some());
        let msg = msg.unwrap();
        assert!(msg.contains("v2/orderbook"));
    }

    #[test]
    fn test_build_orderbook_subscribe_mexc() {
        let msg = build_orderbook_subscribe(15, &["BTCUSDT".to_string()]);
        assert!(msg.is_some());
        let msg = msg.unwrap();
        assert!(msg.contains("btcusdt@depth20@100ms"));
    }

    #[test]
    fn test_build_orderbook_subscribe_ibank() {
        let msg = build_orderbook_subscribe(16, &["BTCUSDT".to_string()]);
        assert!(msg.is_some());
        let msg = msg.unwrap();
        assert!(msg.contains("book:BTCUSDT"));
    }

    #[test]
    fn test_parse_binance_depth() {
        let raw = r#"{
            "lastUpdateId": 160,
            "b": [["50000.00","1.500"],["49999.00","2.000"]],
            "a": [["50001.00","0.500"],["50002.00","1.000"]]
        }"#;
        let delta = parse_orderbook_update(0, "BTCUSDT", raw).unwrap();
        assert!(delta.is_snapshot);
        assert_eq!(delta.last_update_id, 160);
        assert_eq!(delta.bid_updates.len(), 2);
        assert_eq!(delta.ask_updates.len(), 2);
        assert_eq!(delta.bid_updates[0].0, dec!(50000));
        assert_eq!(delta.bid_updates[0].1, dec!(1.5));
    }

    #[test]
    fn test_parse_okx_book_snapshot() {
        let raw = r#"{
            "arg":{"channel":"books5","instId":"BTC-USDT"},
            "action":"snapshot",
            "data":[{
                "bids":[["50000","1","0","1"],["49999","2","0","2"]],
                "asks":[["50001","1","0","1"],["50002","1","0","2"]],
                "seqId":"12345"
            }]
        }"#;
        let delta = parse_orderbook_update(2, "BTCUSDT", raw).unwrap();
        assert!(delta.is_snapshot);
        assert_eq!(delta.last_update_id, 12345);
        assert_eq!(delta.bid_updates.len(), 2);
        assert_eq!(delta.ask_updates.len(), 2);
    }

    #[test]
    fn test_parse_bybit_snapshot() {
        let raw = r#"{
            "topic":"orderbook.100.BTCUSDT",
            "type":"snapshot",
            "data":{
                "s":"BTCUSDT",
                "b":[["50000.00","1"],["49999.00","2"]],
                "a":[["50001.00","1"],["50002.00","2"]],
                "u":100,
                "seq":50000
            },
            "ts":1672515782136
        }"#;
        let delta = parse_orderbook_update(1, "BTCUSDT", raw).unwrap();
        assert!(delta.is_snapshot);
        assert_eq!(delta.last_update_id, 100);
        assert_eq!(delta.bid_updates.len(), 2);
    }

    #[test]
    fn test_parse_bitmex_partial() {
        let raw = r#"{
            "table":"orderBookL2_25",
            "action":"partial",
            "data":[
                {"symbol":"XBTUSDT","id":8000000200,"side":"Buy","size":1,"price":"50000.0"},
                {"symbol":"XBTUSDT","id":8000000201,"side":"Sell","size":2,"price":"50001.0"}
            ]
        }"#;
        let delta = parse_orderbook_update(7, "BTCUSDT", raw).unwrap();
        assert!(delta.is_snapshot);
        assert_eq!(delta.bid_updates.len(), 1);
        assert_eq!(delta.ask_updates.len(), 1);
        assert_eq!(delta.bid_updates[0].0, dec!(50000));
        assert_eq!(delta.bid_updates[0].1, dec!(1));
        assert_eq!(delta.ask_updates[0].0, dec!(50001));
        assert_eq!(delta.ask_updates[0].1, dec!(2));
    }

    #[test]
    fn test_parse_coinbase_snapshot() {
        let raw = r#"{
            "type":"snapshot",
            "product_id":"BTC-USDT",
            "bids":[["50000.00","1"],["49999.00","2"]],
            "asks":[["50001.00","0.5"],["50002.00","1"]]
        }"#;
        let delta = parse_orderbook_update(8, "BTCUSDT", raw).unwrap();
        assert!(delta.is_snapshot);
        assert_eq!(delta.bid_updates.len(), 2);
        assert_eq!(delta.ask_updates.len(), 2);
    }

    #[test]
    fn test_parse_coinbase_l2_update() {
        let raw = r#"{
            "type":"l2_update",
            "product_id":"BTC-USDT",
            "changes":[["buy","50000.50","3.0"],["sell","50001.50","1.5"]]
        }"#;
        let delta = parse_orderbook_update(8, "BTCUSDT", raw).unwrap();
        assert!(!delta.is_snapshot);
        assert_eq!(delta.bid_updates.len(), 1);
        assert_eq!(delta.ask_updates.len(), 1);
        assert_eq!(delta.bid_updates[0].0, dec!(50000.50));
        assert_eq!(delta.ask_updates[0].0, dec!(50001.50));
    }

    #[test]
    fn test_parse_gateio_book() {
        let raw = r#"{
            "time":1234567890123,
            "channel":"spot.order_book",
            "event":"update",
            "result":{
                "s":"BTC_USDT",
                "bids":[["50000","1.5"],["49999","2.0"]],
                "asks":[["50001","0.5"]],
                "lastUpdateId":42
            }
        }"#;
        let delta = parse_orderbook_update(3, "BTCUSDT", raw).unwrap();
        assert_eq!(delta.bid_updates.len(), 2);
        assert_eq!(delta.ask_updates.len(), 1);
        assert_eq!(delta.last_update_id, 42);
    }

    #[test]
    fn test_parse_generic_fallback() {
        // Simulate an unknown exchange sending standard format
        let raw = r#"{
            "bids":[["50000","1.0"]],
            "asks":[["50001","1.0"]]
        }"#;
        let delta = parse_orderbook_update(99, "BTCUSDT", raw).unwrap();
        assert_eq!(delta.bid_updates.len(), 1);
        assert_eq!(delta.ask_updates.len(), 1);
    }

    #[test]
    fn test_parse_ignores_non_book_messages() {
        // Binance subscription confirmation
        let raw = r#"{"result":null,"id":1}"#;
        assert!(parse_orderbook_update(0, "BTCUSDT", raw).is_none());

        // OKX subscription confirmation
        let raw = r#"{"event":"subscribe","arg":{"channel":"books5","instId":"BTC-USDT"}}"#;
        assert!(parse_orderbook_update(2, "BTCUSDT", raw).is_none());

        // Empty string
        assert!(parse_orderbook_update(0, "BTCUSDT", "").is_none());

        // Garbage
        assert!(parse_orderbook_update(0, "BTCUSDT", "not json at all!!!").is_none());
    }

    #[test]
    fn test_parse_bitmex_delete_action() {
        let raw = r#"{
            "table":"orderBookL2_25",
            "action":"delete",
            "data":[
                {"symbol":"XBTUSDT","id":8000000200,"side":"Buy","size":0,"price":"50000.0"}
            ]
        }"#;
        let delta = parse_orderbook_update(7, "BTCUSDT", raw).unwrap();
        assert!(!delta.is_snapshot);
        assert_eq!(delta.bid_updates.len(), 1);
        assert_eq!(delta.bid_updates[0].1, Decimal::ZERO); // Zero qty = delete
    }

    #[test]
    fn test_find_quote_separator() {
        assert_eq!(find_quote_separator("BTCUSDT"), 3);
        assert_eq!(find_quote_separator("ETHUSDT"), 3);
        assert_eq!(find_quote_separator("BTCUSDC"), 3);
        assert_eq!(find_quote_separator("BTCEUR"), 3);
    }

    #[test]
    fn test_symbol_converters() {
        assert_eq!(symbol_to_okx("BTCUSDT"), "BTC-USDT");
        assert_eq!(symbol_to_gateio("BTCUSDT"), "BTC_USDT");
        assert_eq!(symbol_to_bitfinex("BTCUSDT"), "tBTC_USDT");
        assert_eq!(symbol_to_bitmex("BTCUSDT"), "XBTUSDT");
        assert_eq!(symbol_to_coinbase("BTCUSDT"), "BTC-USDT");
        assert_eq!(symbol_to_kraken("BTCUSDT"), "XBT/USDT");
        assert_eq!(symbol_to_kraken("ETHUSDT"), "ETH/USDT");
    }
}