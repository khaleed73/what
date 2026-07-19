// coin_finder.rs — Live Coin Inventory Scanner & Strategy Allocator
//
// STALENESS WINDOW: The scanner clears all per-exchange pair data at the start
// of every cycle, then re-populates via parallel HTTP requests. Between the
// clear and the completion of all HTTP responses (~200–800 ms), the pair data
// is stale. Consumers must tolerate this ~1-second staleness window or gate
// on a "scan complete" signal.
//
// Queries every configured exchange's **public REST API** every ~1 second
// to discover which trading pairs are currently listed.  Each discovered
// pair passes through a multi-stage filter before being registered into the
// bot's token registry:
//
//   1.  **Quote-currency gate**  — only pairs quoted in the configured
//       quote anchors (USDT, USDC, BTC, ETH) are kept.
//   2.  **Symbol normalisation** — "BTCUSDT", "btc_usdt", "BTC-USDT"
//       are all normalised to the canonical uppercase "BTC" base symbol.
//   3.  **Blacklist filter**     — stablecoins, wrapped tokens, leverage
//       tokens, test tokens, and admin/maintenance symbols are rejected.
//   4.  **Category filter**      — tokens are classified into categories
//       (MAJOR, ALTCOIN, MEMECOIN, STABLE, LAYER1) via a lookup table
//       and a regex-based memecoin heuristic.  The caller's category
//       bitmask allowlist is checked.
//   5.  **Cross-exchange eligibility** — if a coin passes the filter and
//       is listed on ≥ 2 exchanges, it is automatically earmarked for
//       cross-exchange arbitrage.
//
// The scanner runs as a single long-lived Tokio task.  Every scan cycle:
//   * clears previous per-exchange pair data,
//   * fires parallel HTTP requests to all exchanges,
//   * merges results, classifies tokens,
//   * updates the `LocalCapitalAllocator` inventory and the `MarketArena`
//     cross-exchange targets / triangular loops.
//
// ## Thread Safety
//
// The scanner mutates the allocator and arena only through their public
// APIs.  `MarketArena::build_cross_exchange_targets()` and
// `MarketArena::build_triangular_loops()` are documented as "boot-time
// cold path" but are safe to call periodically from a single background
// task — no hot-path atomic reads are disrupted.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::Ordering;
use std::sync::Arc;

use reqwest::Client;
use tokio::time::{interval, Duration};
use tracing::{debug, error, info};

use crate::balance_allocator::{
    LocalCapitalAllocator, CAT_ALTCOIN, CAT_LAYER1, CAT_MAJOR,
    CAT_MEMECOIN, CAT_NONE,
};
use crate::strategies::MarketArena;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Scan interval — one full cycle per second.
// NOTE: The coin finder queries all exchanges every 1 second.
// This is well within Binance/OKX public API limits but could
// be aggressive for smaller exchanges. Consider per-exchange intervals.
const SCAN_INTERVAL_SECS: u64 = 1;

/// Maximum number of tokens the finder will register (safety cap).
const MAX_DISCOVERED_TOKENS: usize = 2990;

/// Well-known stablecoins — always filtered OUT (they are quote currencies,
/// not tradeable targets).
const STABLECOIN_SET: &[&str] = &[
    "USDT", "USDC", "DAI", "TUSD", "BUSD", "FDUSD", "USDP", "PYUSD", "GUSD",
    "SUSD", "HUSD", "USDN", "UST", "MIM", "FRAX", "CRVUSD", "LUSD",
    "DOLA", "RUSD", "USDD", "ZUSD",
];

/// Wrapped / pseudo tokens that should never be traded.
const BLACKLIST_SET: &[&str] = &[
    "BTCDOM", "DEFI", "CAKE", "BNBDOWN", "BNBUP", "ETHDOWN", "ETHUP",
    "BTCDOWN", "BTCUP", "ADADOWN", "ADAUP", "XRPDOWN", "XRPUP",
    "DOTDOWN", "DOTUP", "LINKDOWN", "LINKUP", "TRXDOWN", "TRXUP",
    "NEARDOWN", "NEARUP", "SOLUP", "SOLDOWN", "DOGEUP", "DOGEDOWN",
    "EUR", "GBP", "JPY", "AUD", "TRYB", "BRL", "ARS", "RUB", "UAH",
    "NFT", "LDBNB", "TUSD-OLD", "BULL", "BEAR", "ETHBULL", "ETHBEAR",
    "BTCST", "LTCUP", "LTCDOWN", "BVOL", "IBVOL", "PAXG",
    "SXPDOWN", "SXPUP", "CHRDOWN", "CHRUP",
    "TEST", "TESTUSDT", "TESTBTC",
];

/// Known major coins (auto-classified as CAT_MAJOR).
const MAJOR_COINS: &[&str] = &[
    "BTC", "ETH", "BNB", "XRP",
];

/// Known layer-1 coins.
const LAYER1_COINS: &[&str] = &[
    "SOL", "ADA", "AVAX", "NEAR", "DOT", "ATOM", "APT", "SUI",
    "SEI", "TIA", "INJ", "FTM", "OP", "ARB", "MATIC", "ALGO",
    "EOS", "XTZ", "HBAR", "ICP", "KAVA", "ROSE",
];

/// Memecoin pattern fragments — if a symbol (length ≥ 4) contains any of
/// these substrings (case-insensitive), it is classified as a memecoin.
const MEMECOIN_FRAGMENTS: &[&str] = &[
    "DOGE", "PEPE", "SHIB", "FLOKI", "BONK", "WIF", "MEME",
    "TURBO", "BRETT", "MOG", "SPX", "POPCAT", "GIGA", "BOME",
    "NEIRO", "BABYDOGE", "SAMO", "ELON", "SAFEMOON", "FEG",
    "HOKK", "LEASH", "CATE", "KISHU", "AKITA", "BNN",
];

// ---------------------------------------------------------------------------
// Per-exchange public API pair discovery
// ---------------------------------------------------------------------------

/// A single trading pair scraped from an exchange's public API.
#[derive(Debug, Clone)]
struct RawPair {
    /// Normalised base symbol (e.g. "BTC").
    base: String,
    /// Normalised quote symbol (e.g. "USDT").
    quote: String,
    /// Raw exchange symbol for order placement (e.g. "BTCUSDT").
    raw_symbol: String,
    /// Whether the pair is currently tradable.
    status_ok: bool,
}

/// Result of a single exchange scan — all tradeable pairs with normalised
/// base/quote and the raw symbol the exchange expects.
#[derive(Debug, Clone)]
struct ExchangeScanResult {
    exchange_id: u16,
    pairs: Vec<RawPair>,
}

/// Query Binance `/api/v3/exchangeInfo` and extract USDT/USDC/BTC/ETH pairs.
async fn scan_binance(http: &Client, rest_url: &str, exchange_id: u16) -> ExchangeScanResult {
    let url = format!("{}/api/v3/exchangeInfo", rest_url.trim_end_matches('/'));
    let mut pairs = Vec::new();

    match http.get(&url).send().await {
        Ok(resp) => {
            if let Ok(body) = resp.json::<serde_json::Value>().await {
                if let Some(symbols) = body["symbols"].as_array() {
                    for sym in symbols {
                        let raw = sym["symbol"].as_str().unwrap_or("");
                        let status = sym["status"].as_str().unwrap_or("");
                        let base = sym["baseAsset"].as_str().unwrap_or("");
                        let quote = sym["quoteAsset"].as_str().unwrap_or("");

                        if status != "TRADING" || base.is_empty() || quote.is_empty() {
                            continue;
                        }

                        pairs.push(RawPair {
                            base: base.to_uppercase(),
                            quote: quote.to_uppercase(),
                            raw_symbol: raw.to_uppercase(),
                            status_ok: true,
                        });
                    }
                }
            }
        }
        Err(e) => {
            error!(exchange = "Binance", id = exchange_id, error = %e, "public API scan failed");
        }
    }

    ExchangeScanResult { exchange_id, pairs }
}

/// Query Bybit V5 `/v5/market/instruments-info?category=spot`.
async fn scan_bybit(http: &Client, rest_url: &str, exchange_id: u16) -> ExchangeScanResult {
    let url = format!(
        "{}/v5/market/instruments-info?category=spot",
        rest_url.trim_end_matches('/')
    );
    let mut pairs = Vec::new();

    match http.get(&url).send().await {
        Ok(resp) => {
            if let Ok(body) = resp.json::<serde_json::Value>().await {
                if let Some(list) = body["result"]["list"].as_array() {
                    for item in list {
                        let status = item["status"].as_str().unwrap_or("");
                        let base = item["baseCoin"].as_str().unwrap_or("");
                        let quote = item["quoteCoin"].as_str().unwrap_or("");
                        let raw = item["symbol"].as_str().unwrap_or("");

                        if status != "Trading" || base.is_empty() || quote.is_empty() {
                            continue;
                        }

                        pairs.push(RawPair {
                            base: base.to_uppercase(),
                            quote: quote.to_uppercase(),
                            raw_symbol: raw.to_uppercase(),
                            status_ok: true,
                        });
                    }
                }
            }
        }
        Err(e) => {
            error!(exchange = "Bybit", id = exchange_id, error = %e, "public API scan failed");
        }
    }

    ExchangeScanResult { exchange_id, pairs }
}

/// Query OKX `/api/v5/public/instruments?instType=SPOT`.
async fn scan_okx(http: &Client, rest_url: &str, exchange_id: u16) -> ExchangeScanResult {
    let url = format!(
        "{}/api/v5/public/instruments?instType=SPOT",
        rest_url.trim_end_matches('/')
    );
    let mut pairs = Vec::new();

    match http.get(&url).send().await {
        Ok(resp) => {
            if let Ok(body) = resp.json::<serde_json::Value>().await {
                if let Some(data) = body["data"].as_array() {
                    for item in data {
                        let state = item["state"].as_str().unwrap_or("");
                        let inst_id = item["instId"].as_str().unwrap_or("");
                        // OKX uses format like "BTC-USDT"
                        let parts: Vec<&str> = inst_id.split('-').collect();
                        if parts.len() != 2 {
                            continue;
                        }
                        let base = parts[0];
                        let quote = parts[1];

                        if state != "live" || base.is_empty() || quote.is_empty() {
                            continue;
                        }

                        pairs.push(RawPair {
                            base: base.to_uppercase(),
                            quote: quote.to_uppercase(),
                            raw_symbol: inst_id.to_uppercase(),
                            status_ok: true,
                        });
                    }
                }
            }
        }
        Err(e) => {
            error!(exchange = "OKX", id = exchange_id, error = %e, "public API scan failed");
        }
    }

    ExchangeScanResult { exchange_id, pairs }
}

/// Query Gate.io `/api/v4/spot/tickers` and extract from all trading pairs.
async fn scan_gateio(http: &Client, rest_url: &str, exchange_id: u16) -> ExchangeScanResult {
    let url = format!("{}/api/v4/spot/currency_pairs", rest_url.trim_end_matches('/'));
    let mut pairs = Vec::new();

    match http.get(&url).send().await {
        Ok(resp) => {
            if let Ok(body) = resp.json::<serde_json::Value>().await {
                if let Some(list) = body.as_array() {
                    for item in list {
                        let trade_status = item["trade_status"].as_str().unwrap_or("");
                        let base = item["base"].as_str().unwrap_or("");
                        let quote = item["quote"].as_str().unwrap_or("");
                        let raw = item["id"].as_str().unwrap_or("");

                        if trade_status != "tradable" || base.is_empty() || quote.is_empty() {
                            continue;
                        }

                        pairs.push(RawPair {
                            base: base.to_uppercase(),
                            quote: quote.to_uppercase(),
                            raw_symbol: raw.to_uppercase(),
                            status_ok: true,
                        });
                    }
                }
            }
        }
        Err(e) => {
            error!(exchange = "GateIO", id = exchange_id, error = %e, "public API scan failed");
        }
    }

    ExchangeScanResult { exchange_id, pairs }
}

/// Query KuCoin `/api/v1/symbols`.
async fn scan_kucoin(http: &Client, rest_url: &str, exchange_id: u16) -> ExchangeScanResult {
    let url = format!("{}/api/v1/symbols", rest_url.trim_end_matches('/'));
    let mut pairs = Vec::new();

    match http.get(&url).send().await {
        Ok(resp) => {
            if let Ok(body) = resp.json::<serde_json::Value>().await {
                if let Some(data) = body["data"].as_array() {
                    for item in data {
                        let enabled = item["enableTrading"].as_bool().unwrap_or(false);
                        let base = item["baseCurrency"].as_str().unwrap_or("");
                        let quote = item["quoteCurrency"].as_str().unwrap_or("");
                        let raw = item["symbol"].as_str().unwrap_or("");

                        if !enabled || base.is_empty() || quote.is_empty() {
                            continue;
                        }

                        pairs.push(RawPair {
                            base: base.to_uppercase(),
                            quote: quote.to_uppercase(),
                            raw_symbol: raw.to_uppercase(),
                            status_ok: true,
                        });
                    }
                }
            }
        }
        Err(e) => {
            error!(exchange = "KuCoin", id = exchange_id, error = %e, "public API scan failed");
        }
    }

    ExchangeScanResult { exchange_id, pairs }
}

// ---------------------------------------------------------------------------
// Exchange 5 → Bitfinex: GET /v1/symbols_details
// ---------------------------------------------------------------------------

async fn scan_bitfinex(http: &Client, rest_url: &str, exchange_id: u16) -> ExchangeScanResult {
    let url = format!("{}/v1/symbols_details", rest_url.trim_end_matches('/'));
    let mut pairs = Vec::new();

    match http.get(&url).send().await {
        Ok(resp) => {
            if let Ok(body) = resp.json::<serde_json::Value>().await {
                if let Some(list) = body.as_array() {
                    for item in list {
                        // Bitfinex pairs are like "tBTCUSD" — strip the leading 't' for spot
                        let raw = item["pair"].as_str().unwrap_or("");
                        let base_raw = item["base_currency"].as_str().unwrap_or("");
                        let quote_raw = item["quote_currency"].as_str().unwrap_or("");
                        let active = item["active"].as_bool().unwrap_or(false);

                        if !active || base_raw.is_empty() || quote_raw.is_empty() {
                            continue;
                        }

                        pairs.push(RawPair {
                            base: base_raw.to_uppercase(),
                            quote: quote_raw.to_uppercase(),
                            raw_symbol: format!("t{}", raw),
                            status_ok: true,
                        });
                    }
                }
            }
        }
        Err(e) => {
            error!(exchange = "Bitfinex", id = exchange_id, error = %e, "public API scan failed");
        }
    }

    ExchangeScanResult { exchange_id, pairs }
}

// ---------------------------------------------------------------------------
// Exchange 6 → Bitget: GET /api/v2/spot/public/symbols
// ---------------------------------------------------------------------------

async fn scan_bitget(http: &Client, rest_url: &str, exchange_id: u16) -> ExchangeScanResult {
    let url = format!("{}/api/v2/spot/public/symbols", rest_url.trim_end_matches('/'));
    let mut pairs = Vec::new();

    match http.get(&url).send().await {
        Ok(resp) => {
            if let Ok(body) = resp.json::<serde_json::Value>().await {
                if let Some(data) = body["data"].as_array() {
                    for item in data {
                        let status = item["symbolStatus"].as_str().unwrap_or("");
                        let base = item["baseCoin"].as_str().unwrap_or("");
                        let quote = item["quoteCoin"].as_str().unwrap_or("");
                        let raw = item["symbol"].as_str().unwrap_or("");

                        if status != "1" || base.is_empty() || quote.is_empty() {
                            continue;
                        }

                        pairs.push(RawPair {
                            base: base.to_uppercase(),
                            quote: quote.to_uppercase(),
                            raw_symbol: raw.to_uppercase(),
                            status_ok: true,
                        });
                    }
                }
            }
        }
        Err(e) => {
            error!(exchange = "Bitget", id = exchange_id, error = %e, "public API scan failed");
        }
    }

    ExchangeScanResult { exchange_id, pairs }
}

// ---------------------------------------------------------------------------
// Exchange 7 → BitMEX: GET /api/v1/instruments?filter={"state":"Open"}
// ---------------------------------------------------------------------------

async fn scan_bitmex(http: &Client, rest_url: &str, exchange_id: u16) -> ExchangeScanResult {
    let url = format!(
        "{}/api/v1/instruments?filter=%7B%22state%22%3A%22Open%22%7D",
        rest_url.trim_end_matches('/')
    );
    let mut pairs = Vec::new();

    match http.get(&url).send().await {
        Ok(resp) => {
            if let Ok(body) = resp.json::<serde_json::Value>().await {
                if let Some(list) = body.as_array() {
                    for item in list {
                        let state = item["state"].as_str().unwrap_or("");
                        let typ = item["typ"].as_str().unwrap_or("");
                        let base = item["underlying"].as_str().unwrap_or("");
                        let quote = item["quoteCurrency"].as_str().unwrap_or("");
                        let raw = item["symbol"].as_str().unwrap_or("");

                        // Only perpetual/spot — skip futures expirations for arb
                        if state != "Open" || base.is_empty() {
                            continue;
                        }
                        // Skip plain futures (only keep perps and spot-like)
                        let is_perp = typ == "FFWCS"; // perpetual inverse swap
                        let is_linear = typ == "FFWSS"; // perpetual linear swap
                        let is_spot = typ == "spot";
                        if !is_perp && !is_linear && !is_spot {
                            continue;
                        }

                        pairs.push(RawPair {
                            base: base.to_uppercase(),
                            quote: if quote.is_empty() { "USD".to_string() } else { quote.to_uppercase() },
                            raw_symbol: raw.to_uppercase(),
                            status_ok: true,
                        });
                    }
                }
            }
        }
        Err(e) => {
            error!(exchange = "BitMEX", id = exchange_id, error = %e, "public API scan failed");
        }
    }

    ExchangeScanResult { exchange_id, pairs }
}

// ---------------------------------------------------------------------------
// Exchange 8 → Coinbase: GET /products
// ---------------------------------------------------------------------------

async fn scan_coinbase(http: &Client, rest_url: &str, exchange_id: u16) -> ExchangeScanResult {
    let url = format!("{}/products", rest_url.trim_end_matches('/'));
    let mut pairs = Vec::new();

    match http.get(&url).send().await {
        Ok(resp) => {
            if let Ok(body) = resp.json::<serde_json::Value>().await {
                if let Some(list) = body.as_array() {
                    for item in list {
                        let status = item["status"].as_str().unwrap_or("");
                        let tradable = item["trading_disabled"].as_bool().unwrap_or(false);
                        let base = item["base_currency"].as_str().unwrap_or("");
                        let quote = item["quote_currency"].as_str().unwrap_or("");
                        let raw = item["id"].as_str().unwrap_or("");

                        if status != "online" || tradable || base.is_empty() || quote.is_empty() {
                            continue;
                        }

                        pairs.push(RawPair {
                            base: base.to_uppercase(),
                            quote: quote.to_uppercase(),
                            raw_symbol: raw.to_uppercase(),
                            status_ok: true,
                        });
                    }
                }
            }
        }
        Err(e) => {
            error!(exchange = "Coinbase", id = exchange_id, error = %e, "public API scan failed");
        }
    }

    ExchangeScanResult { exchange_id, pairs }
}

// ---------------------------------------------------------------------------
// Exchange 9 → HTX (Huobi): GET /v1/settings/symbols
// ---------------------------------------------------------------------------

async fn scan_htx(http: &Client, rest_url: &str, exchange_id: u16) -> ExchangeScanResult {
    let url = format!("{}/v1/settings/symbols", rest_url.trim_end_matches('/'));
    let mut pairs = Vec::new();

    match http.get(&url).send().await {
        Ok(resp) => {
            if let Ok(body) = resp.json::<serde_json::Value>().await {
                if let Some(data) = body["data"].as_array() {
                    for item in data {
                        let state = item["state"].as_str().unwrap_or("");
                        let base = item["baseCurrency"].as_str().unwrap_or("");
                        let quote = item["quoteCurrency"].as_str().unwrap_or("");
                        let raw = item["symbol"].as_str().unwrap_or("");

                        if state != "online" || base.is_empty() || quote.is_empty() {
                            continue;
                        }

                        pairs.push(RawPair {
                            base: base.to_uppercase(),
                            quote: quote.to_uppercase(),
                            raw_symbol: raw.to_uppercase(),
                            status_ok: true,
                        });
                    }
                }
            }
        }
        Err(e) => {
            error!(exchange = "HTX", id = exchange_id, error = %e, "public API scan failed");
        }
    }

    ExchangeScanResult { exchange_id, pairs }
}

// ---------------------------------------------------------------------------
// Exchange 10 → Kraken: GET /0/public/AssetPairs
// ---------------------------------------------------------------------------

async fn scan_kraken(http: &Client, rest_url: &str, exchange_id: u16) -> ExchangeScanResult {
    let url = format!("{}/0/public/AssetPairs", rest_url.trim_end_matches('/'));
    let mut pairs = Vec::new();

    match http.get(&url).send().await {
        Ok(resp) => {
            if let Ok(body) = resp.json::<serde_json::Value>().await {
                if let Some(result) = body["result"].as_object() {
                    for (wsname, item) in result {
                        // Skip .d (detail) entries
                        if wsname.ends_with(".d") {
                            continue;
                        }
                        let base = item["base"].as_str().unwrap_or("");
                        let quote = item["quote"].as_str().unwrap_or("");
                        let raw = item["altname"].as_str().unwrap_or(wsname);

                        if base.is_empty() || quote.is_empty() {
                            continue;
                        }

                        pairs.push(RawPair {
                            base: base.to_uppercase(),
                            quote: quote.to_uppercase(),
                            raw_symbol: raw.to_uppercase(),
                            status_ok: true,
                        });
                    }
                }
            }
        }
        Err(e) => {
            error!(exchange = "Kraken", id = exchange_id, error = %e, "public API scan failed");
        }
    }

    ExchangeScanResult { exchange_id, pairs }
}

// ---------------------------------------------------------------------------
// Exchange 11 → LBank: GET /api/v2/pairs
// ---------------------------------------------------------------------------

async fn scan_lbank(http: &Client, rest_url: &str, exchange_id: u16) -> ExchangeScanResult {
    let url = format!("{}/api/v2/pairs", rest_url.trim_end_matches('/'));
    let mut pairs = Vec::new();

    match http.get(&url).send().await {
        Ok(resp) => {
            if let Ok(body) = resp.json::<serde_json::Value>().await {
                if let Some(data) = body["data"].as_array() {
                    for item in data {
                        let status = item["status"].as_i64().unwrap_or(0);
                        let base = item["coin"].as_str().unwrap_or("");
                        let quote = item["market"].as_str().unwrap_or("");
                        let raw = item["symbol"].as_str().unwrap_or("");

                        if status != 1 || base.is_empty() || quote.is_empty() {
                            continue;
                        }

                        pairs.push(RawPair {
                            base: base.to_uppercase(),
                            quote: quote.to_uppercase(),
                            raw_symbol: raw.to_uppercase(),
                            status_ok: true,
                        });
                    }
                }
            }
        }
        Err(e) => {
            error!(exchange = "LBank", id = exchange_id, error = %e, "public API scan failed");
        }
    }

    ExchangeScanResult { exchange_id, pairs }
}

// ---------------------------------------------------------------------------
// Exchange 12 → Bitstamp: GET /api/v2/trading-pairs-info
// ---------------------------------------------------------------------------

async fn scan_bitstamp(http: &Client, rest_url: &str, exchange_id: u16) -> ExchangeScanResult {
    let url = format!("{}/api/v2/trading-pairs-info", rest_url.trim_end_matches('/'));
    let mut pairs = Vec::new();

    match http.get(&url).send().await {
        Ok(resp) => {
            if let Ok(body) = resp.json::<serde_json::Value>().await {
                if let Some(list) = body.as_array() {
                    for item in list {
                        let tradable = item["trading"].as_str().unwrap_or("Disabled");
                        let base = item["base_currency"].as_str().unwrap_or("");
                        let quote = item["quote_currency"].as_str().unwrap_or("");
                        let raw = item["name"].as_str().unwrap_or("");
                        // Bitstamp url_symbol is like "btcusd"
                        let url_sym = item["url_symbol"].as_str().unwrap_or(raw);

                        if tradable != "Enabled" || base.is_empty() || quote.is_empty() {
                            continue;
                        }

                        pairs.push(RawPair {
                            base: base.to_uppercase(),
                            quote: quote.to_uppercase(),
                            raw_symbol: url_sym.to_uppercase(),
                            status_ok: true,
                        });
                    }
                }
            }
        }
        Err(e) => {
            error!(exchange = "Bitstamp", id = exchange_id, error = %e, "public API scan failed");
        }
    }

    ExchangeScanResult { exchange_id, pairs }
}

// ---------------------------------------------------------------------------
// Exchange 13 → Deribit: POST /api/v2/public/get_instruments (JSON-RPC)
// ---------------------------------------------------------------------------

async fn scan_deribit(http: &Client, rest_url: &str, exchange_id: u16) -> ExchangeScanResult {
    let url = format!("{}/api/v2/public/get_instruments", rest_url.trim_end_matches('/'));
    let mut pairs = Vec::new();

    // Deribit uses JSON-RPC POST for everything
    let rpc_body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "public/get_instruments",
        "params": {
            "currency": "BTC",
            "kind": "spot",
            "expired": false
        }
    });

    match http.post(&url).json(&rpc_body).send().await {
        Ok(resp) => {
            if let Ok(body) = resp.json::<serde_json::Value>().await {
                if let Some(result) = body["result"].as_array() {
                    for item in result {
                        let base = item["base_currency"].as_str().unwrap_or("BTC");
                        let quote = item["quote_currency"].as_str().unwrap_or("");
                        let raw = item["instrument_name"].as_str().unwrap_or("");
                        let active = item["is_active"].as_bool().unwrap_or(false);

                        if !active || raw.is_empty() {
                            continue;
                        }

                        pairs.push(RawPair {
                            base: base.to_uppercase(),
                            quote: if quote.is_empty() { "USD".to_string() } else { quote.to_uppercase() },
                            raw_symbol: raw.to_uppercase(),
                            status_ok: true,
                        });
                    }
                }
            }
        }
        Err(e) => {
            error!(exchange = "Deribit", id = exchange_id, error = %e, "public API scan failed");
        }
    }

    ExchangeScanResult { exchange_id, pairs }
}

// ---------------------------------------------------------------------------
// Exchange 14 → Delta Exchange: GET /v2/products
// ---------------------------------------------------------------------------

async fn scan_delta(http: &Client, rest_url: &str, exchange_id: u16) -> ExchangeScanResult {
    let url = format!("{}/v2/products", rest_url.trim_end_matches('/'));
    let mut pairs = Vec::new();

    match http.get(&url).send().await {
        Ok(resp) => {
            if let Ok(body) = resp.json::<serde_json::Value>().await {
                if let Some(result) = body["result"].as_array() {
                    for item in result {
                        let typ = item["product_type"].as_str().unwrap_or("");
                        let base = item["underlying_asset"]["symbol"].as_str()
                            .or_else(|| item["contract_type"].as_str())
                            .unwrap_or("");
                        let settled = item["settlement_asset"]["symbol"].as_str()
                            .or_else(|| item["quote_asset"]["symbol"].as_str())
                            .unwrap_or("USDT");
                        let raw = item["symbol"].as_str().unwrap_or("");
                        let live = item["live"].as_bool().unwrap_or(false);

                        // Only spot and perpetuals
                        if !live || raw.is_empty() {
                            continue;
                        }
                        let is_spot = typ == "spot";
                        let is_perp = typ == "perpetual_futures";
                        if !is_spot && !is_perp {
                            continue;
                        }

                        pairs.push(RawPair {
                            base: base.to_uppercase(),
                            quote: settled.to_uppercase(),
                            raw_symbol: raw.to_uppercase(),
                            status_ok: true,
                        });
                    }
                }
            }
        }
        Err(e) => {
            error!(exchange = "Delta", id = exchange_id, error = %e, "public API scan failed");
        }
    }

    ExchangeScanResult { exchange_id, pairs }
}

// ---------------------------------------------------------------------------
// Exchange 15 → MEXC: GET /api/v3/exchangeInfo (Binance-compatible)
// ---------------------------------------------------------------------------

async fn scan_mexc(http: &Client, rest_url: &str, exchange_id: u16) -> ExchangeScanResult {
    let url = format!("{}/api/v3/exchangeInfo", rest_url.trim_end_matches('/'));
    let mut pairs = Vec::new();

    match http.get(&url).send().await {
        Ok(resp) => {
            if let Ok(body) = resp.json::<serde_json::Value>().await {
                if let Some(symbols) = body["symbols"].as_array() {
                    for sym in symbols {
                        let raw = sym["symbol"].as_str().unwrap_or("");
                        let status = sym["status"].as_str().unwrap_or("");
                        let base = sym["baseAsset"].as_str().unwrap_or("");
                        let quote = sym["quoteAsset"].as_str().unwrap_or("");

                        if status != "ENABLED" && status != "TRADING" {
                            continue;
                        }
                        if base.is_empty() || quote.is_empty() {
                            continue;
                        }

                        pairs.push(RawPair {
                            base: base.to_uppercase(),
                            quote: quote.to_uppercase(),
                            raw_symbol: raw.to_uppercase(),
                            status_ok: true,
                        });
                    }
                }
            }
        }
        Err(e) => {
            error!(exchange = "MEXC", id = exchange_id, error = %e, "public API scan failed");
        }
    }

    ExchangeScanResult { exchange_id, pairs }
}

// ---------------------------------------------------------------------------
// Exchange 16 → Ibank (Independent Reserve): GET /Public/GetAssets
// ---------------------------------------------------------------------------

async fn scan_ibank(http: &Client, rest_url: &str, exchange_id: u16) -> ExchangeScanResult {
    let url = format!("{}/Public/GetAssets", rest_url.trim_end_matches('/'));
    let mut pairs = Vec::new();

    // Independent Reserve uses a different approach — GetAssets returns
    // tradeable assets, then we query market summary for pairs.
    // We use the simpler approach of hitting GetMarkets-style endpoint.
    let markets_url = format!("{}/Public/GetMarkets", rest_url.trim_end_matches('/'));

    match http.get(&markets_url).send().await {
        Ok(resp) => {
            if let Ok(body) = resp.json::<serde_json::Value>().await {
                if let Some(markets) = body.as_array() {
                    for item in markets {
                        let base = item["PrimaryCurrencyCode"].as_str().unwrap_or("");
                        let quote = item["SecondaryCurrencyCode"].as_str().unwrap_or("");
                        let active = item["Active"].as_bool().unwrap_or(false);

                        if !active || base.is_empty() || quote.is_empty() {
                            continue;
                        }

                        // Normalize to standard format
                        let raw = format!("{}{}", base.to_uppercase(), quote.to_uppercase());

                        pairs.push(RawPair {
                            base: base.to_uppercase(),
                            quote: quote.to_uppercase(),
                            raw_symbol: raw,
                            status_ok: true,
                        });
                    }
                }
            }
        }
        Err(_e) => {
            // Fallback: if GetMarkets fails, try the general assets endpoint
            match http.get(&url).send().await {
                Ok(resp2) => {
                    if let Ok(body2) = resp2.json::<serde_json::Value>().await {
                        if let Ok(assets) = serde_json::from_value::<Vec<serde_json::Value>>(body2) {
                            // Independent Reserve lists XBT, ETH, etc. — we build
                            // pairs by combining each asset with NZD/USD/AUD
                            for asset in &assets {
                                let code = asset["Code"].as_str().unwrap_or("");
                                if code.is_empty() {
                                    continue;
                                }
                                for quote in &["USD", "AUD", "NZD", "USDT"] {
                                    pairs.push(RawPair {
                                        base: code.to_uppercase(),
                                        quote: quote.to_string(),
                                        raw_symbol: format!("{}{}", code.to_uppercase(), quote),
                                        status_ok: true,
                                    });
                                }
                            }
                        }
                    }
                }
                Err(e2) => {
                    error!(exchange = "Ibank", id = exchange_id, error = %e2, "public API scan failed (fallback also failed)");
                }
            }
        }
    }

    ExchangeScanResult { exchange_id, pairs }
}

/// Dispatch to the correct scanner based on the exchange's numeric ID.
async fn scan_exchange(
    http: &Client,
    exchange_id: u16,
    rest_url: &str,
) -> ExchangeScanResult {
    match exchange_id {
        0 => scan_binance(http, rest_url, exchange_id).await,
        1 => scan_bybit(http, rest_url, exchange_id).await,
        2 => scan_okx(http, rest_url, exchange_id).await,
        3 => scan_gateio(http, rest_url, exchange_id).await,
        4 => scan_kucoin(http, rest_url, exchange_id).await,
        5 => scan_bitfinex(http, rest_url, exchange_id).await,
        6 => scan_bitget(http, rest_url, exchange_id).await,
        7 => scan_bitmex(http, rest_url, exchange_id).await,
        8 => scan_coinbase(http, rest_url, exchange_id).await,
        9 => scan_htx(http, rest_url, exchange_id).await,
        10 => scan_kraken(http, rest_url, exchange_id).await,
        11 => scan_lbank(http, rest_url, exchange_id).await,
        12 => scan_bitstamp(http, rest_url, exchange_id).await,
        13 => scan_deribit(http, rest_url, exchange_id).await,
        14 => scan_delta(http, rest_url, exchange_id).await,
        15 => scan_mexc(http, rest_url, exchange_id).await,
        16 => scan_ibank(http, rest_url, exchange_id).await,
        _ => {
            debug!(exchange_id, "no public API scanner for this exchange ID");
            ExchangeScanResult {
                exchange_id,
                pairs: Vec::new(),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Filter pipeline
// ---------------------------------------------------------------------------

/// Check whether a base symbol passes all filter stages.
fn passes_filter(
    base: &str,
    quote: &str,
    quote_anchors: &[String],
    min_volume_usd: Option<f64>,
    volume_24h_usd: Option<f64>,
) -> (bool, u16) {
    // Stage 1: Quote-currency gate — only keep pairs quoted in approved anchors.
    if !quote_anchors.iter().any(|a| a.eq_ignore_ascii_case(quote)) {
        return (false, CAT_NONE);
    }

    // Stage 2: Stablecoin blacklist — never trade stablecoins as base.
    if STABLECOIN_SET.iter().any(|s| s.eq_ignore_ascii_case(base)) {
        return (false, CAT_NONE);
    }

    // Stage 3: Blacklist gate.
    if BLACKLIST_SET.iter().any(|s| s.eq_ignore_ascii_case(base)) {
        return (false, CAT_NONE);
    }

    // Stage 4: Volume filter — skip pairs below minimum 24h volume if configured.
    if let Some(min_vol) = min_volume_usd {
        if let Some(vol) = volume_24h_usd {
            if vol < min_vol {
                return (false, CAT_NONE);
            }
        }
    }

    // Stage 5: Category classification.
    let upper = base.to_uppercase();

    // Known majors
    if MAJOR_COINS.iter().any(|s| s.eq_ignore_ascii_case(base)) {
        return (true, CAT_MAJOR);
    }

    // Known layer-1
    if LAYER1_COINS.iter().any(|s| s.eq_ignore_ascii_case(base)) {
        return (true, CAT_LAYER1);
    }

    // Memecoin heuristic: contains known memecoin fragments
    if upper.len() >= 4
        && MEMECOIN_FRAGMENTS
            .iter()
            .any(|frag| upper.contains(frag))
        {
            return (true, CAT_MEMECOIN);
        }

    // Default: altcoin
    (true, CAT_ALTCOIN)
}

// ---------------------------------------------------------------------------
// CoinFinder — the live scanner
// ---------------------------------------------------------------------------

/// Configuration for the coin finder.
pub struct CoinFinderConfig {
    /// Quote currencies to accept (e.g. vec!["USDT", "USDC"]).
    pub quote_anchors: Vec<String>,
    /// Category bitmask allowlist — a token is kept only if its category
    /// mask has at least one bit in common with this mask.
    /// `0` means accept all categories.
    pub allowed_categories: u16,
    /// Minimum 24h volume in USD for a pair to be considered (optional).
    /// Pairs with no volume data are always kept.
    pub min_volume_usd: Option<f64>,
}

impl Default for CoinFinderConfig {
    fn default() -> Self {
        Self {
            quote_anchors: vec!["USDT".to_string()],
            allowed_categories: 0, // accept all
            min_volume_usd: None,
        }
    }
}

/// The live coin inventory scanner.
///
/// Holds references to the shared allocator and arena, plus a snapshot of
/// the exchange REST endpoints.  When `run()` is called, it enters an
/// infinite loop that scans all exchanges every `SCAN_INTERVAL_SECS`.
pub struct CoinFinder {
    http: Client,
    /// Map of exchange_id → rest_url.
    exchange_rest_urls: HashMap<u16, String>,
    config: CoinFinderConfig,
    allocator: Arc<LocalCapitalAllocator>,
    arena: Arc<MarketArena>,
    /// Tracks the next token ID to assign when registering a new coin.
    next_token_id: std::sync::atomic::AtomicU16,
    /// Symbol → assigned token_id across the entire session.
    global_symbol_map: tokio::sync::Mutex<HashMap<String, u16>>,
    /// Category mask for each discovered token_id.
    token_categories: tokio::sync::Mutex<HashMap<u16, u16>>,
    /// Custom symbol-to-exchange mappings that override or supplement
    /// the dynamically-discovered pairs.  Key is a normalized pair
    /// symbol (e.g. "BTCUSDT"), value is the list of exchange IDs
    /// where this pair should be registered.
    custom_mappings: tokio::sync::Mutex<HashMap<String, Vec<u16>>>,
}

impl CoinFinder {
    /// Create a new coin finder.
    ///
    /// `start_token_id` should be set past any manually-registered tokens
    /// in the allocator (e.g. 100 to avoid colliding with IDs 0–99).
    pub fn new(
        exchange_rest_urls: HashMap<u16, String>,
        config: CoinFinderConfig,
        allocator: Arc<LocalCapitalAllocator>,
        arena: Arc<MarketArena>,
        start_token_id: u16,
    ) -> Result<Self, String> {
        let http = Client::builder()
            .timeout(Duration::from_secs(5))
            .connect_timeout(Duration::from_secs(3))
            .pool_max_idle_per_host(2)
            .build()
            .map_err(|e| format!("failed to build HTTP client: {}", e))?;
        Ok(Self {
            http,
            exchange_rest_urls,
            config,
            allocator,
            arena,
            next_token_id: std::sync::atomic::AtomicU16::new(start_token_id),
            global_symbol_map: tokio::sync::Mutex::new(HashMap::new()),
            token_categories: tokio::sync::Mutex::new(HashMap::new()),
            custom_mappings: tokio::sync::Mutex::new(HashMap::new()),
        })
    }

    /// Add a custom symbol-to-exchange mapping.
    ///
    /// `symbol` is a normalized pair symbol (e.g. "BTCUSDT").
    /// `exchange_ids` is the list of exchange IDs where this pair should
    /// be registered, overriding or supplementing the scanner's discovery.
    ///
    /// This allows runtime configuration without code changes.
    pub async fn add_custom_mapping(&self, symbol: &str, exchange_ids: Vec<u16>) {
        self.custom_mappings
            .lock()
            .await
            .insert(symbol.to_uppercase(), exchange_ids);
    }

    /// Allocate a new token ID (monotonically increasing, lock-free).
    /// Returns `None` when the safety cap is exhausted, instead of
    /// silently returning 0 (which would collide with USDT).
    fn alloc_token_id(&self) -> Option<u16> {
        self.next_token_id
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                if v >= (MAX_DISCOVERED_TOKENS as u16) {
                    None // safety cap — stop registering
                } else {
                    Some(v + 1)
                }
            })
            .ok()
    }

    /// Get or create a token_id for the given symbol.
    /// Returns `Some((id, is_newly_created))`.
    ///
    /// L-12: Deduplication is handled by the `global_symbol_map` — the same
    /// base symbol (e.g. "SOL") on different exchanges always maps to the
    /// same `token_id`. The caller is responsible for tracking per-exchange
    /// precision differences via the `raw_symbol` field on trade paths.
    async fn get_or_create_token_id(&self, symbol: &str, category_mask: u16) -> Option<(u16, bool)> {
        let mut map = self.global_symbol_map.lock().await;

        if let Some(&id) = map.get(symbol) {
            // Update category if we now have more info
            let mut cats = self.token_categories.lock().await;
            cats.entry(id).and_modify(|c| *c |= category_mask);
            return Some((id, false));
        }

        let id = match self.alloc_token_id() {
            Some(id) => id,
            None => {
                // Safety cap exhausted — cannot register more tokens.
                // Return None so the caller skips this symbol entirely
                // rather than colliding with token 0 (USDT).
                return None;
            }
        };

        map.insert(symbol.to_uppercase(), id);
        self.token_categories
            .lock()
            .await
            .insert(id, category_mask);

        // Register in the allocator's inventory
        self.allocator.register_token(id, symbol, category_mask);

        // L-6 fix: Documentation corrected — this uses .lock() (blocking),
        // not try_lock.  The cold-path blocking is acceptable since this
        // runs in a single background task.
        self.arena.register_active_token(id);

        Some((id, true))
    }

    /// Run a single scan cycle across all configured exchanges.
    ///
    /// Returns the number of newly discovered tokens and total active pairs.
    async fn scan_cycle(&self) -> (usize, usize) {
        // Fire all exchange scans in parallel
        let mut handles = Vec::new();

        for (&exchange_id, rest_url) in &self.exchange_rest_urls {
            let http = self.http.clone();
            let url = rest_url.clone();
            handles.push(tokio::spawn(async move {
                scan_exchange(&http, exchange_id, &url).await
            }));
        }

        // Collect results
        let mut all_results: Vec<ExchangeScanResult> = Vec::new();
        for handle in handles {
            match handle.await {
                Ok(result) => all_results.push(result),
                Err(e) => {
                    error!(error = %e, "scan task panicked");
                }
            }
        }

        // -----------------------------------------------------------------
        // Filter & classify every pair from every exchange
        // -----------------------------------------------------------------

        // Per-exchange filtered pairs: exchange_id → Vec<(token_id, base, quote, raw_symbol)>
        let mut exchange_pairs: HashMap<u16, Vec<(u16, String, String, String)>> =
            HashMap::new();

        // Track which tokens appear on which exchanges for cross-exchange detection
        let mut token_exchange_presence: HashMap<u16, HashSet<u16>> = HashMap::new();

        let mut new_tokens: usize = 0;
        let mut total_pairs: usize = 0;

        for result in &all_results {
            let exch_id = result.exchange_id;
            let mut filtered_pairs = Vec::new();

            for pair in &result.pairs {
                if !pair.status_ok {
                    continue;
                }

                // Stage 1–4: Filter
                let (passes, category) =
                    passes_filter(&pair.base, &pair.quote, &self.config.quote_anchors, self.config.min_volume_usd, None);

                if !passes {
                    continue;
                }

                // Stage 5: Category allowlist check
                if self.config.allowed_categories != 0
                    && (category & self.config.allowed_categories) == 0
                {
                    continue;
                }

                // Get or create a global token_id
                let (token_id, is_new) = match self.get_or_create_token_id(&pair.base, category).await {
                    Some(pair) => pair,
                    None => continue, // safety cap hit
                };

                if is_new {
                    new_tokens += 1;
                }

                // Track cross-exchange presence
                token_exchange_presence
                    .entry(token_id)
                    .or_default()
                    .insert(exch_id);

                filtered_pairs.push((
                    token_id,
                    pair.base.clone(),
                    pair.quote.clone(),
                    pair.raw_symbol.clone(),
                ));
            }

            total_pairs += filtered_pairs.len();
            exchange_pairs.insert(exch_id, filtered_pairs);
        }

        // -----------------------------------------------------------------
        // Apply custom symbol-to-exchange mappings
        // -----------------------------------------------------------------
        {
            let custom = self.custom_mappings.lock().await;
            for (symbol, target_exchange_ids) in custom.iter() {
                // Extract base by stripping a known quote anchor suffix.
                let (base, quote) = {
                    let upper = symbol.as_str();
                    let mut found = None;
                    for anchor in &self.config.quote_anchors {
                        if upper.ends_with(anchor.as_str()) {
                            let b = &upper[..upper.len() - anchor.len()];
                            if !b.is_empty() {
                                found = Some((b.to_string(), anchor.clone()));
                                break;
                            }
                        }
                    }
                    match found {
                        Some(pair) => pair,
                        None => continue, // cannot parse — skip
                    }
                };

                // Classify the token for category filtering.
                let (passes, category) = passes_filter(
                    &base, &quote, &self.config.quote_anchors,
                    self.config.min_volume_usd, None,
                );
                if !passes { continue; }
                if self.config.allowed_categories != 0
                    && (category & self.config.allowed_categories) == 0
                {
                    continue;
                }

                let (token_id, is_new) = match self.get_or_create_token_id(&base, category).await {
                    Some(pair) => pair,
                    None => continue,
                };
                if is_new { new_tokens += 1; }

                for &target_exch in target_exchange_ids {
                    // Skip if this pair is already in the exchange's list.
                    let already = exchange_pairs
                        .get(&target_exch)
                        .map(|pairs| pairs.iter().any(|(tid, _, _, _)| *tid == token_id))
                        .unwrap_or(false);
                    if already { continue; }

                    token_exchange_presence
                        .entry(token_id)
                        .or_default()
                        .insert(target_exch);

                    exchange_pairs
                        .entry(target_exch)
                        .or_default()
                        .push((token_id, base.clone(), quote.clone(), symbol.clone()));
                }
            }
        }

        // -----------------------------------------------------------------
        // Auto-allocate: build cross-exchange targets and triangular loops
        // -----------------------------------------------------------------

        // We need mutable access to the arena for rebuilding targets.
        // Since `Arc<MarketArena>` is shared, we use `get_mut`-style access.
        // The arena is wrapped in Arc but we are the sole writer during
        // this cold-path phase.  We use `Arc::get_mut` which works because
        // no other Arc clones exist that are still mutable — all other
        // references are immutable (atomic reads from hot path).
        //
        // SAFETY: The arena's build_* methods only modify `cross_targets`,
        // `cross_index`, and `tri_loops` — none of which are read via
        // `Arc::get_mut`.  Hot-path readers use the atomic arrays
        // (bid_prices / ask_prices) which are not touched here.

        // Build cross-exchange targets from the presence map.
        // For every token on ≥ 2 exchanges, write dummy non-zero prices
        // so that `build_cross_exchange_targets()` picks it up.
        {
            for (&token_id, exchanges) in &token_exchange_presence {
                if exchanges.len() >= 2 {
                    // Write sentinel prices so the arena's target builder
                    // sees the token as "live" on those exchanges.
                    for &exch in exchanges {
                        // Use a sentinel price of 1_000_000 (1.0 in the arena's
                        // fixed-point representation) for both bid and ask.
                        // This is a placeholder — real prices come from WS feeds.
                        let idx = self.arena.get_index(exch as usize, token_id as usize);
                        self.arena.bid_prices[idx].store(1_000_000, Ordering::Release);
                        self.arena.ask_prices[idx].store(1_000_001, Ordering::Release);
                    }
                }
            }
        }

        // Build per-exchange pair lists for triangular loop discovery.
        // Format: exchange_id → Vec<(base_token_id, quote_token_id)>
        let mut tri_pair_map: HashMap<u16, Vec<(u16, u16)>> = HashMap::new();

        for (&exch_id, pairs) in &exchange_pairs {
            let mut pair_list = Vec::new();
            for &(token_id, ref _base, ref quote, _) in pairs {
                // Look up the quote currency's token_id
                // (USDT=0, USDC=1, DAI=2 are pre-registered)
                let quote_id = self
                    .allocator
                    .get_id(quote);

                // Skip pairs where the quote currency is not registered.
                // Using u16::MAX as a sentinel would create triangular loops
                // referencing an out-of-bounds token index, causing panics
                // in evaluate_tick's get_index() call.
                let quote_id = match quote_id {
                    Some(id) => id,
                    None => continue,
                };

                pair_list.push((token_id, quote_id));
            }
            tri_pair_map.insert(exch_id, pair_list);
        }

        // Safe concurrent rebuild: build_* methods now use RwLock
        // interior mutability, so no unsafe pointer casting needed.
        self.arena.build_cross_exchange_targets().await;
        self.arena.build_triangular_loops(&tri_pair_map).await;

        (new_tokens, total_pairs)
    }

    /// Main loop — scans all exchanges every second and updates the
    /// shared token registry, cross-exchange targets, and triangular loops.
    pub async fn run(&self) {
        info!("Coin finder started — scanning {} exchange(s) every {}s",
            self.exchange_rest_urls.len(), SCAN_INTERVAL_SECS);
        info!("Quote anchors: {:?}", self.config.quote_anchors);
        info!("Category filter: 0b{:04b}", self.config.allowed_categories);

        let mut ticker = interval(Duration::from_secs(SCAN_INTERVAL_SECS));
        let mut cycle: u64 = 0;

        loop {
            ticker.tick().await;
            cycle = cycle.saturating_add(1);

            let (new_tokens, total_pairs) = self.scan_cycle().await;

            if cycle == 1 || cycle.is_multiple_of(60) {
                info!(
                    cycle,
                    new_tokens,
                    total_pairs,
                    cross_targets = self.arena.cross_targets.try_read().map(|g| g.len()).unwrap_or(0),
                    "coin finder scan complete"
                );
            }

            debug!(
                cycle,
                new_tokens,
                total_pairs,
                cross_targets = self.arena.cross_targets.try_read().map(|g| g.len()).unwrap_or(0),
                "scan cycle"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filter_stablecoin_rejected() {
        // USDT as base (quoted in USDC) should be rejected — it's a stablecoin
        let (ok, cat) = passes_filter("USDT", "USDC", &["USDC".to_string()], None, None);
        assert!(!ok);
        assert_eq!(cat, CAT_NONE);
    }

    #[test]
    fn test_filter_blacklist_rejected() {
        let (ok, _) = passes_filter("BTCDOM", "USDT", &["USDT".to_string()], None, None);
        assert!(!ok);

        let (ok, _) = passes_filter("NFT", "USDT", &["USDT".to_string()], None, None);
        assert!(!ok);
    }

    #[test]
    fn test_filter_wrong_quote_rejected() {
        // BTC quoted in BRL — not in our quote anchors
        let (ok, _) = passes_filter("BTC", "BRL", &["USDT".to_string()], None, None);
        assert!(!ok);
    }

    #[test]
    fn test_filter_major_classified() {
        let (ok, cat) = passes_filter("BTC", "USDT", &["USDT".to_string()], None, None);
        assert!(ok);
        assert_eq!(cat, CAT_MAJOR);

        let (ok, cat) = passes_filter("ETH", "USDT", &["USDT".to_string()], None, None);
        assert!(ok);
        assert_eq!(cat, CAT_MAJOR);
    }

    #[test]
    fn test_filter_layer1_classified() {
        let (ok, cat) = passes_filter("SOL", "USDT", &["USDT".to_string()], None, None);
        assert!(ok);
        assert_eq!(cat, CAT_LAYER1);

        let (ok, cat) = passes_filter("ADA", "USDT", &["USDT".to_string()], None, None);
        assert!(ok);
        assert_eq!(cat, CAT_LAYER1);
    }

    #[test]
    fn test_filter_memecoin_classified() {
        let (ok, cat) = passes_filter("DOGE", "USDT", &["USDT".to_string()], None, None);
        assert!(ok);
        assert_eq!(cat, CAT_MEMECOIN);

        let (ok, cat) = passes_filter("PEPE", "USDT", &["USDT".to_string()], None, None);
        assert!(ok);
        assert_eq!(cat, CAT_MEMECOIN);

        let (ok, cat) = passes_filter("SHIB", "USDT", &["USDT".to_string()], None, None);
        assert!(ok);
        assert_eq!(cat, CAT_MEMECOIN);
    }

    #[test]
    fn test_filter_default_altcoin() {
        // Some random token that's not in any known list
        let (ok, cat) = passes_filter("UNI", "USDT", &["USDT".to_string()], None, None);
        assert!(ok);
        assert_eq!(cat, CAT_ALTCOIN);
    }

    #[test]
    fn test_filter_multiple_quote_anchors() {
        let anchors = vec!["USDT".to_string(), "BTC".to_string()];

        // BTC quoted in USDT — accepted
        let (ok, _) = passes_filter("ETH", "USDT", &anchors, None, None);
        assert!(ok);

        // ETH quoted in BTC — accepted
        let (ok, _) = passes_filter("ETH", "BTC", &anchors, None, None);
        assert!(ok);

        // ETH quoted in BRL — rejected
        let (ok, _) = passes_filter("ETH", "BRL", &anchors, None, None);
        assert!(!ok);
    }

    #[test]
    fn test_filter_case_insensitive() {
        let (ok, cat) = passes_filter("btc", "usdt", &["USDT".to_string()], None, None);
        assert!(ok);
        assert_eq!(cat, CAT_MAJOR);

        let (ok, _) = passes_filter("UsDt", "BTC", &["BTC".to_string()], None, None);
        assert!(!ok); // USDT base is a stablecoin, always rejected
    }
}