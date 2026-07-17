use crate::strategies::MarketArena;
use crate::rebalancer::ExchangeHeartbeatHandle;
use futures_util::{SinkExt, StreamExt};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::time::{sleep, Duration};
use tokio_tungstenite::connect_async;
use serde_json;
use rand::Rng;
use tracing::{error, info, warn};

// ---------------------------------------------------------------------------
// Zero-allocation hot-path parser
// ---------------------------------------------------------------------------

/// Scans raw JSON bytes for single-char keys `"t"`, `"b"`, `"a"` and extracts
/// their numeric values without any heap allocation.
///
/// Returns `Some((token_id, bid_price, ask_price))` on success or `None` if
/// any required field is missing / malformed.
///
/// Price values (`"b"`, `"a"`) are parsed as fixed-point integers: decimal
/// points in the JSON are simply skipped so that e.g. `"50000.50"` becomes
/// `5000050u64`.
#[inline]
pub fn parse_raw_bytes_fast(payload: &[u8]) -> Option<(u16, u64, u64)> {
    let mut token_id: Option<u16> = None;
    let mut bid_price: Option<u64> = None;
    let mut ask_price: Option<u64> = None;

    let len = payload.len();
    let mut i = 0;

    while i < len {
        // Look for opening quote of a key
        if payload[i] != b'"' {
            i += 1;
            continue;
        }

        // We found '"'.  Next byte must be the key character.
        i += 1;
        if i >= len {
            break;
        }

        let key = payload[i];
        i += 1;

        // Expect closing quote
        if i >= len || payload[i] != b'"' {
            continue;
        }
        i += 1;

        // Expect colon
        if i >= len || payload[i] != b':' {
            continue;
        }
        i += 1;

        // Skip whitespace / newline after colon
        while i < len && (payload[i] == b' ' || payload[i] == b'\n' || payload[i] == b'\r' || payload[i] == b'\t') {
            i += 1;
        }

        if i >= len {
            break;
        }

        match key {
            b't' => {
                // Parse u16 — may be negative? No, token IDs are positive.
                let (val, next) = parse_u16_at(payload, i)?;
                token_id = Some(val);
                i = next;
            }
            b'b' => {
                let (val, next) = parse_u64_skip_dot(payload, i)?;
                bid_price = Some(val);
                i = next;
            }
            b'a' => {
                let (val, next) = parse_u64_skip_dot(payload, i)?;
                ask_price = Some(val);
                i = next;
            }
            _ => {
                // Unknown key — advance to next '"' or end to keep scanning.
                while i < len && payload[i] != b'"' {
                    i += 1;
                }
            }
        }
    }

    match (token_id, bid_price, ask_price) {
        (Some(t), Some(b), Some(a)) => Some((t, b, a)),
        _ => None,
    }
}

/// Parse an unsigned 16-bit integer starting at `pos`.  Handles optional
/// leading minus (returns None for negatives).  Returns the value and the
/// index of the first byte *after* the number.
#[inline]
fn parse_u16_at(bytes: &[u8], mut pos: usize) -> Option<(u16, usize)> {
    let len = bytes.len();
    let start = pos;
    while pos < len && bytes[pos].is_ascii_digit() {
        pos += 1;
    }
    if pos == start {
        return None;
    }
    // Build the number manually to avoid substring allocation
    let mut val: u16 = 0;
    let mut cursor = start;
    while cursor < pos {
        let digit = bytes[cursor] - b'0';
        val = val.checked_mul(10)?.checked_add(digit as u16)?;
        cursor += 1;
    }
    Some((val, pos))
}

/// Parse digits into a u64, normalizing to exactly `TARGET_DECIMALS`
/// decimal places.  This converts fixed-point JSON numbers like `50000.50`
/// into `50000500000000` (9-decimal fixed-point), ensuring that `50000.50`
/// and `5000.050` produce *different* values (50000500000000 vs
/// 5000050000000).
///
/// Without this normalization, `50000.50` and `5000.050` would both
/// yield `5000050`, causing the bot to misprice assets and execute
/// losing trades.
const TARGET_DECIMALS: u32 = 9;

#[inline]
fn parse_u64_skip_dot(bytes: &[u8], mut pos: usize) -> Option<(u64, usize)> {
    let len = bytes.len();
    let start = pos;

    // First pass: find the end of the number and count decimal places.
    let mut dot_seen = false;
    let mut decimal_places: u32 = 0;
    let scan_end = pos;
    let mut i = pos;
    while i < len && (bytes[i].is_ascii_digit() || bytes[i] == b'.') {
        if bytes[i] == b'.' {
            if dot_seen {
                break; // second dot — stop
            }
            dot_seen = true;
        } else if dot_seen {
            decimal_places += 1;
        }
        i += 1;
    }
    let end = i;

    if end == start {
        return None;
    }

    // Parse digits into a raw integer (skipping dots).
    let mut raw_val: u64 = 0;
    let mut cursor = start;
    while cursor < end {
        let b = bytes[cursor];
        if b == b'.' {
            cursor += 1;
            continue;
        }
        let digit = b - b'0';
        raw_val = raw_val.checked_mul(10)?.checked_add(digit as u64)?;
        cursor += 1;
    }

    // Normalize to TARGET_DECIMALS decimal places.
    // raw_val has `decimal_places` fractional digits; we need `TARGET_DECIMALS`.
    let normalized = if decimal_places <= TARGET_DECIMALS {
        // Pad with zeros: multiply by 10^(TARGET_DECIMALS - decimal_places)
        let pad = TARGET_DECIMALS - decimal_places;
        match raw_val.checked_mul(10u64.checked_pow(pad)?) {
            Some(v) => v,
            None => return None, // overflow
        }
    } else {
        // Truncate: divide by 10^(decimal_places - TARGET_DECIMALS)
        let trim = decimal_places - TARGET_DECIMALS;
        let divisor = match 10u64.checked_pow(trim) {
            Some(v) => v,
            None => {
                tracing::warn!(trim = trim, "price_normalization: 10^pow overflow, returning None");
                return None;
            }
        };
        raw_val / divisor
    };

    Some((normalized, end))
}

// ---------------------------------------------------------------------------
// WebSocket listener
// ---------------------------------------------------------------------------

pub struct LowLatencyWsListener {
    pub exchange_id: u16,
    pub wss_url: String,
    pub arena: Arc<MarketArena>,
    /// Receives updated symbol lists from the coin finder.
    /// The WS listener re-subscribes with the latest symbols on reconnect.
    pub symbol_watch: tokio::sync::watch::Receiver<Vec<String>>,
    /// Optional handle to record exchange heartbeats for the rebalancer's
    /// liveness check.  When `Some`, every successfully parsed WS message
    /// records a heartbeat so the rebalancer knows this exchange is alive.
    pub heartbeat: Option<ExchangeHeartbeatHandle>,
}

impl LowLatencyWsListener {
    pub fn new(
        exchange_id: u16,
        wss_url: String,
        arena: Arc<MarketArena>,
        symbol_watch: tokio::sync::watch::Receiver<Vec<String>>,
    ) -> Self {
        Self {
            exchange_id,
            wss_url,
            arena,
            symbol_watch,
            heartbeat: None,
        }
    }

    /// Set the heartbeat handle.  Call this after construction to enable
    /// rebalancer liveness tracking for this exchange's feed worker.
    pub fn with_heartbeat(mut self, handle: ExchangeHeartbeatHandle) -> Self {
        self.heartbeat = Some(handle);
        self
    }

    /// Connects to the WebSocket endpoint and streams price updates into the
    /// shared `MarketArena`.  On error the connection is re-established after
    /// an exponential back-off (1s, 2s, 4s, …, capped at 30s).
    /// A close frame terminates the loop.
    pub async fn start_streaming(&self) {
        let ex = self.exchange_id;
        info!(exchange_id = ex, url = %self.wss_url, "starting ws listener");

        let mut consecutive_failures: u32 = 0;
        const BASE_DELAY_SECS: u64 = 1;
        const MAX_DELAY_SECS: u64 = 30;
        const MAX_CONSECUTIVE_FAILURES: u32 = 50; // ~16 min of retries at cap

        loop {
            // Wrap connect in a 10-second timeout to prevent hung DNS/TCP/TLS.
            let connect_result = tokio::time::timeout(
                std::time::Duration::from_secs(10),
                connect_async(&self.wss_url),
            ).await;

            match connect_result {
                Ok(Ok((ws_stream, _response))) => {
                    // Successful connection — reset failure counter.
                    consecutive_failures = 0;
                    info!(exchange_id = ex, "websocket connected");

                    let (mut write, mut read) = ws_stream.split();

                    // Send subscription message immediately after connecting.
                    // Uses the latest symbols from the coin finder (via watch channel).
                    let current_symbols = self.symbol_watch.borrow().clone();
                    if let Some(sub_msg) = build_subscribe_message(self.exchange_id, &current_symbols) {
                        if let Err(e) = write.send(tokio_tungstenite::tungstenite::Message::Text(sub_msg)).await {
                            error!(exchange_id = ex, error = %e, "failed to send WS subscribe message");
                            break;
                        }
                    }

                    while let Some(msg) = read.next().await {
                        match msg {
                            Ok(tokio_tungstenite::tungstenite::Message::Text(text)) => {
                                // Reject oversized messages to prevent OOM from
                                // a malicious or buggy server.
                                if text.len() > 65_536 {
                                    warn!(
                                        exchange_id = ex,
                                        msg_len = text.len(),
                                        "WS message exceeds 64 KiB, dropping"
                                    );
                                    continue;
                                }
                                if let Some((token_id, bid, ask)) =
                                    parse_raw_bytes_fast(text.as_bytes())
                                {
                                    self.arena.update_price(
                                        self.exchange_id as usize,
                                        token_id as usize,
                                        bid,
                                        ask,
                                    );
                                    // Record heartbeat for the rebalancer's
                                    // liveness check (no-op if handle is None).
                                    if let Some(ref hb) = self.heartbeat {
                                        hb.record(self.exchange_id);
                                    }
                                }
                            }
                            Ok(tokio_tungstenite::tungstenite::Message::Close(_)) => {
                                info!(exchange_id = ex, "websocket close received, stopping");
                                return;
                            }
                            Ok(_) => {
                                // Ignore Ping / Pong / Binary frames
                            }
                            Err(e) => {
                                error!(exchange_id = ex, error = %e, "websocket read error");
                                break;
                            }
                        }
                    }

                    warn!(exchange_id = ex, "ws stream ended, reconnecting");
                }
                Ok(Err(e)) => {
                    consecutive_failures += 1;
                    if consecutive_failures > MAX_CONSECUTIVE_FAILURES {
                        error!(
                            exchange_id = ex,
                            consecutive_failures,
                            "WS connect failed {} times in a row — giving up, feed worker exiting",
                            MAX_CONSECUTIVE_FAILURES
                        );
                        return;
                    }
                    let base_delay = (BASE_DELAY_SECS << consecutive_failures.saturating_sub(1))
                        .min(MAX_DELAY_SECS) as f64;
                    let jittered = base_delay * (0.8 + 0.4 * rand::thread_rng().gen::<f64>());
                    let delay_secs = jittered.min(MAX_DELAY_SECS as f64) as u64;
                    error!(
                        exchange_id = ex,
                        error = %e,
                        consecutive_failures,
                        delay_secs,
                        "websocket connect error, reconnecting with jittered exponential backoff"
                    );
                    sleep(Duration::from_secs(delay_secs.max(1))).await;
                    continue;
                }
                Err(e) => {
                    consecutive_failures += 1;
                    if consecutive_failures > MAX_CONSECUTIVE_FAILURES {
                        error!(
                            exchange_id = ex,
                            consecutive_failures,
                            "WS connect failed {} times in a row — giving up, feed worker exiting",
                            MAX_CONSECUTIVE_FAILURES
                        );
                        return;
                    }
                    let base_delay = (BASE_DELAY_SECS << consecutive_failures.saturating_sub(1))
                        .min(MAX_DELAY_SECS) as f64;
                    let jittered = base_delay * (0.8 + 0.4 * rand::thread_rng().gen::<f64>());
                    let delay_secs = jittered.min(MAX_DELAY_SECS as f64) as u64;
                    error!(
                        exchange_id = ex,
                        error = %e,
                        consecutive_failures,
                        delay_secs,
                        "websocket connect failed, reconnecting with jittered exponential backoff"
                    );
                    sleep(Duration::from_secs(delay_secs.max(1))).await;
                    continue;
                }
            }

            // Stream ended (not a connect failure) — use same backoff logic.
            consecutive_failures += 1;
            if consecutive_failures > MAX_CONSECUTIVE_FAILURES {
                error!(
                    exchange_id = ex,
                    consecutive_failures,
                    "WS stream ended {} times — giving up, feed worker exiting",
                    MAX_CONSECUTIVE_FAILURES
                );
                return;
            }
            let base_delay = (BASE_DELAY_SECS << consecutive_failures.saturating_sub(1))
                .min(MAX_DELAY_SECS) as f64;
            let jittered = base_delay * (0.8 + 0.4 * rand::thread_rng().gen::<f64>());
            let delay_secs = jittered.min(MAX_DELAY_SECS as f64) as u64;
            warn!(
                exchange_id = ex,
                consecutive_failures,
                delay_secs,
                "reconnecting with jittered exponential backoff"
            );
            sleep(Duration::from_secs(delay_secs.max(1))).await;
        }
    }
}

// ---------------------------------------------------------------------------
// Spawner
// ---------------------------------------------------------------------------

/// Spawns one tokio task per exchange, each running a `LowLatencyWsListener`.
/// Returns the vector of `JoinHandle`s so the caller can await or abort them.
///
/// `symbol_watch` is a `watch::Receiver` carrying the latest discovered symbol
/// list.  Each WS listener re-subscribes with the current symbols on every
/// reconnect.  The coin finder writes new symbol lists via the sender half.
///
/// `heartbeat` is an optional `ExchangeHeartbeatHandle` from the rebalancer.
/// When provided, each feed worker records a heartbeat on every parsed WS
/// message, keeping the rebalancer's exchange liveness map fresh.
pub fn spawn_feed_workers(
    arena: Arc<MarketArena>,
    exchanges: Vec<(u16, String)>,
    symbol_watch: tokio::sync::watch::Receiver<Vec<String>>,
    heartbeat: Option<ExchangeHeartbeatHandle>,
) -> Vec<tokio::task::JoinHandle<()>> {
    let mut handles = Vec::with_capacity(exchanges.len());

    for (exchange_id, wss_url) in exchanges {
        let listener = LowLatencyWsListener::new(
            exchange_id,
            wss_url,
            Arc::clone(&arena),
            symbol_watch.clone(),
        );
        // Clone the heartbeat handle for this worker (Arc clone, cheap).
        let listener = if let Some(ref hb) = heartbeat {
            listener.with_heartbeat(hb.clone())
        } else {
            listener
        };
        let handle = tokio::spawn(async move {
            listener.start_streaming().await;
        });
        handles.push(handle);
    }

    handles
}

/// Known quote currencies ordered longest-first so that `USDT` is tried
/// before `USDC` / `BUSD`, preventing greedy mis-splits.
const KNOWN_QUOTES: &[&str] = &["USDT", "USDC", "BUSD", "BTC", "ETH", "BNB"];

/// Split a concatenated symbol (e.g. `BTCUSDT`) into `(base, quote)`.
///
/// Probes `KNOWN_QUOTES` from longest to shortest and splits at the first
/// match found at the **end** of the symbol.  Falls back to `(symbol, "")`
/// when no known quote matches (the caller can then use the symbol unchanged).
#[inline]
fn split_base_quote(symbol: &str) -> (&str, &str) {
    for &quote in KNOWN_QUOTES {
        if symbol.ends_with(quote) {
            let base = &symbol[..symbol.len() - quote.len()];
            if !base.is_empty() {
                return (base, quote);
            }
        }
    }
    (symbol, "")
}

/// Build a subscription message for the exchange.
/// Returns None for exchanges that don't require subscription (e.g. KuCoin REST token).
///
/// `symbols` is a dynamic list of ticker symbols (e.g. `["BTCUSDT", "ETHUSDT"]`).
/// Falls back to `["BTCUSDT", "ETHUSDT"]` if the list is empty.
/// GateIO uses a live timestamp to avoid signature rejection.
///
/// # Symbol splitting
///
/// Several exchanges require the base/quote to be separated (e.g. `BTC-USDT`
/// instead of `BTCUSDT`).  Rather than assuming a fixed 3-character quote, we
/// probe a set of known quote currencies (`USDT`, `USDC`, `BUSD`, `BTC`,
/// `ETH`, `BNB`) and split at the longest match.  If no known quote is found
/// the symbol is passed through unchanged.
fn build_subscribe_message(exchange_id: u16, symbols: &[String]) -> Option<String> {
    // Accepts a dynamic symbol list; falls back to BTC/ETH if empty.
    // The coin finder populates additional pairs after boot.
    let syms: Vec<&str> = if symbols.is_empty() {
        vec!["BTCUSDT", "ETHUSDT"]
    } else {
        symbols.iter().map(|s| s.as_str()).collect()
    };

    match exchange_id {
        // Binance — lowercase, @ticker suffix
        0 => {
            let params: Vec<String> = syms.iter().map(|s| format!("{}@ticker", s.to_lowercase())).collect();
            Some(format!(r#"{{"method":"subscribe","params":{:?}}}"#, params))
        }
        // Bybit — tickers. prefix
        1 => {
            let args: Vec<String> = syms.iter().map(|s| format!("tickers.{}", s)).collect();
            Some(format!(r#"{{"op":"subscribe","args":{:?}}}"#, args))
        }
        // OKX — hyphen separator (BTCUSDT -> BTC-USDT)
        2 => {
            let args: Vec<serde_json::Value> = syms.iter().map(|s| {
                let (base, quote) = split_base_quote(s);
                let inst_id = if quote.is_empty() {
                    s.to_string()
                } else {
                    format!("{}-{}", base, quote)
                };
                serde_json::json!({"channel": "tickers", "instId": inst_id})
            }).collect();
            Some(format!(r#"{{"op":"subscribe","args":{}}}"#, serde_json::to_string(&args).unwrap_or_default()))
        }
        // GateIO — underscore separator, LIVE timestamp
        3 => {
            let ts = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0);
            let payload: Vec<String> = syms.iter().map(|s| {
                let (base, quote) = split_base_quote(s);
                if quote.is_empty() {
                    s.to_string()
                } else {
                    format!("{}_{}", base, quote)
                }
            }).collect();
            Some(format!(r#"{{"time":{},"channel":"spot.tickers","event":"subscribe","payload":{:?}}}"#, ts, payload))
        }
        // KuCoin — REST-obtained WS token, handled by coin_finder
        4 => None,
        // Exchange 5 → Bitfinex: subscribe to ticker channel
        5 => {
            // Bitfinex uses channel ID based subscriptions
            // Format: { "event": "subscribe", "channel": "ticker", "symbol": "tBTCUSD" }
            let subs: Vec<serde_json::Value> = syms.iter().map(|s| {
                let (base, quote) = split_base_quote(s);
                let sym = if quote.is_empty() {
                    format!("t{}", s)
                } else {
                    format!("t{}_{}", base, quote)
                };
                serde_json::json!({"event": "subscribe", "channel": "ticker", "symbol": sym})
            }).collect();
            // Bitfinex subscribes to multiple symbols in a single message array
            Some(serde_json::to_string(&subs).unwrap_or_default())
        }
        // Exchange 6 → Bitget: tickers channel
        6 => {
            let args: Vec<String> = syms.iter().map(|s| format!("tickers.{}", s)).collect();
            Some(format!(r#"{{"op":"subscribe","args":{:?}}}"#, args))
        }
        // Exchange 7 → BitMEX: subscribe to instrument
        7 => {
            let subs: Vec<serde_json::Value> = syms.iter().map(|s| {
                serde_json::json!({"op": "subscribe", "args": [format!("instrument:{}", s)]})
            }).collect();
            Some(serde_json::to_string(&subs).unwrap_or_default())
        }
        // Exchange 8 → Coinbase: subscribe to ticker channel
        8 => {
            let product_ids: Vec<String> = syms.iter().map(|s| {
                let (base, quote) = split_base_quote(s);
                if quote.is_empty() {
                    s.to_string()
                } else {
                    format!("{}-{}", base, quote)
                }
            }).collect();
            let sub_msg = serde_json::json!({
                "type": "subscribe",
                "product_ids": product_ids,
                "channels": ["ticker"]
            });
            Some(serde_json::to_string(&sub_msg).unwrap_or_default())
        }
        // Exchange 9 → HTX: subscribe to market.tickers topic
        9 => {
            // HTX uses "sub" format with data sources
            let subs: Vec<String> = syms.iter().map(|s| format!("market.tickers.{}", s)).collect();
            Some(format!(r#"{{"sub":{:?},"id":"hft_sub"}}"#, subs))
        }
        // Exchange 10 → Kraken: subscribe to ticker channel
        10 => {
            // Kraken uses a pair-based subscribe
            let pair_subs: Vec<serde_json::Value> = syms.iter().map(|s| {
                // Kraken uses XBT not BTC for WS
                let pair = s.replace("BTCUSDT", "XBT/USDT")
                    .replace("BTC", "XBT");
                serde_json::json!({"name": "ticker", "pair": pair})
            }).collect();
            let sub_msg = serde_json::json!({
                "event": "subscribe",
                "pair": pair_subs.iter().filter_map(|v| v["pair"].as_str()).collect::<Vec<_>>(),
                "subscription": {"name": "ticker"}
            });
            Some(serde_json::to_string(&sub_msg).unwrap_or_default())
        }
        // Exchange 11 → LBank: subscribe to tickers
        11 => {
            let sub_msg = serde_json::json!({
                "action": "subscribe",
                "subscribe": "tickers",
                "pair": syms
            });
            Some(serde_json::to_string(&sub_msg).unwrap_or_default())
        }
        // Exchange 12 → Bitstamp: subscribe to live_trades for ticker data
        12 => {
            let channel_subs: Vec<serde_json::Value> = syms.iter().map(|s| {
                serde_json::json!({
                    "event": "bts:subscribe",
                    "data": { "channel": format!("live_trades_{}", s.to_lowercase()) }
                })
            }).collect();
            Some(serde_json::to_string(&channel_subs).unwrap_or_default())
        }
        // Exchange 13 → Deribit: JSON-RPC subscribe to ticker
        13 => {
            let channels: Vec<String> = syms.iter().map(|s| format!("ticker.{}.100ms", s)).collect();
            let sub_msg = serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "public/subscribe",
                "params": { "channels": channels }
            });
            Some(serde_json::to_string(&sub_msg).unwrap_or_default())
        }
        // Exchange 14 → Delta: subscribe to ticker channel
        14 => {
            let subs: Vec<serde_json::Value> = syms.iter().map(|s| {
                serde_json::json!({
                    "type": "subscribe",
                    "payload": { "channel": "v2/ticker", "symbols": [s] }
                })
            }).collect();
            Some(serde_json::to_string(&subs).unwrap_or_default())
        }
        // Exchange 15 → MEXC: Binance-compatible WS subscription
        15 => {
            let params: Vec<String> = syms.iter().map(|s| format!("{}@ticker", s.to_lowercase())).collect();
            Some(format!(r#"{{"method":"subscribe","params":{:?}}}"#, params))
        }
        // Exchange 16 → Ibank (Independent Reserve): uses WebSocket orderbook channel
        16 => {
            // Ibank WS uses Delta Exchange-style WebSocket API
            // Subscribe to ticker updates
            let channels: Vec<String> = syms.iter().map(|s| format!("ticker:{}", s)).collect();
            Some(format!(r#"{{"op":"subscribe","args":{:?}}}"#, channels))
        }
        // Unknown exchange — Binance-style fallback
        _ => {
            let params: Vec<String> = syms.iter().map(|s| format!("{}@ticker", s.to_lowercase())).collect();
            Some(format!(r#"{{"method":"subscribe","params":{:?}}}"#, params))
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_valid_payload() {
        let payload = b"{\"t\":42,\"b\":50000.50,\"a\":50001.25}";
        let result = parse_raw_bytes_fast(payload);
        // 50000.50 → 50000500000000 (9-decimal FP)
        // 50001.25 → 50001250000000
        assert_eq!(result, Some((42, 50000500000000, 50001250000000)));
    }

    #[test]
    fn test_precision_different_decimals() {
        // CRITICAL: 50000.50 and 5000.050 must NOT produce the same value.
        let p1 = b"{\"t\":1,\"b\":50000.50,\"a\":1}";
        let p2 = b"{\"t\":1,\"b\":5000.050,\"a\":1}";
        let r1 = parse_raw_bytes_fast(p1).unwrap();
        let r2 = parse_raw_bytes_fast(p2).unwrap();
        assert_ne!(r1.1, r2.1, "50000.50 and 5000.050 must differ!");
    }

    #[test]
    fn test_parse_empty_payload() {
        let payload = b"this is garbage !!!";
        let result = parse_raw_bytes_fast(payload);
        assert_eq!(result, None);
    }

    #[test]
    fn test_parse_missing_fields() {
        // Only token_id present — bid and ask are missing so we must get None.
        let payload = b"{\"t\":7}";
        let result = parse_raw_bytes_fast(payload);
        assert_eq!(result, None);
    }

    #[test]
    fn test_split_base_quote() {
        // Standard USDT pairs
        assert_eq!(split_base_quote("BTCUSDT"), ("BTC", "USDT"));
        assert_eq!(split_base_quote("ETHUSDT"), ("ETH", "USDT"));
        // USDC pairs (also 4 chars, but different quote)
        assert_eq!(split_base_quote("BTCUSDC"), ("BTC", "USDC"));
        // BUSD pairs
        assert_eq!(split_base_quote("ETHBUSD"), ("ETH", "BUSD"));
        // Short symbol — no match
        assert_eq!(split_base_quote("BTC"), ("BTC", ""));
        // Unknown quote — passed through
        assert_eq!(split_base_quote("DOGEUSDT"), ("DOGE", "USDT"));
        // Edge: symbol that ends with USDT but is short
        assert_eq!(split_base_quote("AUSDT"), ("A", "USDT"));
    }
}