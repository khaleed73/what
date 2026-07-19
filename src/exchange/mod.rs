// exchange/mod.rs — Rich exchange framework module root.
//
// Provides:
// * A full-featured `Exchange` trait (order books, cancels, health, etc.)
// * 17 production exchange client implementations
// * Shared signing utilities, rate limiting, error types
//
// This sits alongside the simpler `crate::exchanges` module which
// implements `crate::signer::PrivateExchangeClient` for the HFT
// execution engine.  The two frameworks are independent but share
// the same `reqwest`, `ring`, and `rust_decimal` dependencies.

pub mod common;
pub mod config;
pub mod exchange_trait;
pub mod types;

// Individual exchange client modules
pub mod binance;
pub mod bitfinex;
pub mod bitget;
pub mod bitmex;
pub mod bitstamp;
pub mod bybit;
pub mod coinbase;
pub mod delta;
pub mod deribit;
pub mod gateio;
pub mod htx;
pub mod ibank;
pub mod kraken;
pub mod kucoin;
pub mod lbank;
pub mod mexc;
pub mod okx;

// Exchange name mapping (extends the one in crate::exchanges)
//
// IMPORTANT: The u64 bitmask system used in strategies.rs and market_arena.rs
// can represent at most 64 exchanges (bits 0..63).  If new exchanges are added
// beyond index 63, the bitmask will silently overflow.  Validate that the
// number of registered exchanges never exceeds 64.
pub fn exchange_name_by_id(id: u16) -> &'static str {
    match id {
        0 => "Binance",
        1 => "Bybit",
        2 => "OKX",
        3 => "GateIO",
        4 => "KuCoin",
        5 => "Bitfinex",
        6 => "Bitget",
        7 => "BitMEX",
        8 => "Coinbase",
        9 => "HTX",
        10 => "Kraken",
        11 => "LBank",
        12 => "Bitstamp",
        13 => "Deribit",
        14 => "Delta",
        15 => "MEXC",
        16 => "Ibank",
        _ => {
            tracing::warn!("exchange_name_by_id: unknown exchange id {}", id);
            "UNKNOWN"
        }
    }
}

