// exchange/types.rs — Shared types for the rich Exchange trait framework.
//
// These types are used by all exchange client implementations in the
// `exchange` module.  They provide a superset of the simpler types in
// `crate::signer` (which remain for the HFT execution engine).

use rust_decimal::Decimal;

// ---------------------------------------------------------------------------
// OrderSide
// ---------------------------------------------------------------------------

/// Side of an order (buy or sell).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrderSide {
    Buy,
    Sell,
}

// ---------------------------------------------------------------------------
// OrderType
// ---------------------------------------------------------------------------

/// Type of an order (market, limit, stop).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrderType {
    Market,
    Limit,
    StopLimit,
    StopMarket,
}

// ---------------------------------------------------------------------------
// TimeInForce
// ---------------------------------------------------------------------------

/// Time-in-force policy for limit orders.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeInForce {
    GTC,
    IOC,
    FOK,
    Day,
}

// ---------------------------------------------------------------------------
// OrderRequest — richer version for the Exchange trait
// ---------------------------------------------------------------------------

/// Richer order request for the Exchange trait.
#[derive(Debug, Clone)]
pub struct OrderRequest {
    pub symbol: String,
    pub side: OrderSide,
    pub quantity: Decimal,
    pub client_order_id: Option<String>,
    pub time_in_force: TimeInForce,
    pub stop_price: Option<Decimal>,
}

// ---------------------------------------------------------------------------
// OrderResponse — rich response from the Exchange trait
// ---------------------------------------------------------------------------

/// Rich response from the Exchange trait.
#[derive(Debug, Clone)]
pub struct OrderResponse {
    pub order_id: String,
    pub client_order_id: String,
    pub status: String,
    pub filled_qty: Decimal,
    pub avg_price: Decimal,
    pub exchange: String,
    pub fee: Option<Decimal>,
    pub fee_currency: Option<String>,
    pub slippage_bps: Option<Decimal>,
    pub created_at_ms: Option<u64>,
    pub updated_at_ms: Option<u64>,
    pub deadline_ms: Option<u64>,
}

// ---------------------------------------------------------------------------
// OrderBook
// ---------------------------------------------------------------------------

/// A single price level in an order book.
#[derive(Debug, Clone)]
pub struct OrderBookLevel {
    pub price: Decimal,
    pub quantity: Decimal,
}

/// A snapshot of an exchange's order book at a point in time.
#[derive(Debug, Clone)]
pub struct OrderBookSnapshot {
    pub symbol: String,
    pub exchange: String,
    pub bids: Vec<OrderBookLevel>,
    pub asks: Vec<OrderBookLevel>,
    pub timestamp_us: u64,
}

// ---------------------------------------------------------------------------
// ExchangeType — discriminant for each exchange
// ---------------------------------------------------------------------------

/// Exchange type discriminant for each exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExchangeType {
    Binance,
    Bybit,
    Okx,
    Gateio,
    KuCoin,
    Bitfinex,
    Bitget,
    Bitmex,
    Coinbase,
    Htx,
    Kraken,
    LBank,
    Bitstamp,
    Deribit,
    Delta,
    Mexc,
    Ibank,
}