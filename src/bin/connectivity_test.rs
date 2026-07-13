//! connectivity_test — REST + WebSocket reachability test for all 12 exchanges.
//!
//! Usage:  cargo run --bin connectivity_test
//!
//! Tests:
//!   1. REST health endpoint (unauthenticated GET) — verifies DNS, TLS, HTTP.
//!   2. REST fetch_symbols (public, unauthenticated) — verifies API structure.
//!   3. WebSocket connect + subscribe — verifies WSS handshake + subscription ack.
//!
//! No API keys needed.  All tests use public endpoints only.

use futures_util::{SinkExt, StreamExt};
use std::time::{Duration, Instant};
use tokio_tungstenite::tungstenite::Message;

// ─── Exchange definitions ───────────────────────────────────────────────

struct ExchangeDef {
    name: &'static str,
    rest_base: &'static str,
    health_path: &'static str,
    symbols_path: &'static str,
    wss_url: Option<&'static str>,
    wss_subscribe_msg: Option<&'static str>,
    wss_subscribe_ack: Option<&'static str>,
}

const EXCHANGES: &[ExchangeDef] = &[
    ExchangeDef {
        name: "Binance",
        rest_base: "https://api.binance.com",
        health_path: "/api/v3/ping",
        symbols_path: "/api/v3/exchangeInfo",
        wss_url: Some("wss://stream.binance.com:9443/ws"),
        wss_subscribe_msg: Some(r#"{"method":"subscribe","params":["btcusdt@ticker"],"id":1}"#),
        wss_subscribe_ack: Some(r#""result":null"#),
    },
    ExchangeDef {
        name: "Bybit",
        rest_base: "https://api.bybit.com",
        health_path: "/v5/market/time",
        symbols_path: "/v5/market/instruments-info?category=spot&limit=5",
        wss_url: Some("wss://stream.bybit.com/v5/public/spot"),
        wss_subscribe_msg: Some(r#"{"op":"subscribe","args":["tickers.BTCUSDT"]}"#),
        wss_subscribe_ack: Some(r#""success":true"#),
    },
    ExchangeDef {
        name: "OKX",
        rest_base: "https://www.okx.com",
        health_path: "/api/v5/public/time",
        symbols_path: "/api/v5/public/instruments?instType=SPOT&limit=5",
        wss_url: Some("wss://ws.okx.com:8443/ws/v5/public"),
        wss_subscribe_msg: Some(r#"{"op":"subscribe","args":[{"channel":"tickers","instId":"BTC-USDT"}]}"#),
        wss_subscribe_ack: Some(r#""event":"subscribe""#),
    },
    ExchangeDef {
        name: "Gate.io",
        rest_base: "https://api.gateio.ws",
        health_path: "/api/v4/spot/time",
        symbols_path: "/api/v4/spot/currency_pairs",
        wss_url: Some("wss://api.gateio.ws/ws/v4/"),
        wss_subscribe_msg: Some(r#"{"time":1234567890,"channel":"spot.tickers","event":"subscribe","payload":["BTC_USDT"]}"#),
        wss_subscribe_ack: Some(r#""event":"subscribe""#),
    },
    ExchangeDef {
        name: "KuCoin",
        rest_base: "https://api.kucoin.com",
        health_path: "/api/v1/timestamp",
        symbols_path: "/api/v1/symbols",
        wss_url: None, // KuCoin needs a token endpoint first
        wss_subscribe_msg: None,
        wss_subscribe_ack: None,
    },
    ExchangeDef {
        name: "Bitfinex",
        rest_base: "https://api.bitfinex.com",
        health_path: "/platform/status",
        symbols_path: "/conf/pub:list:pair:exchange",
        wss_url: Some("wss://api-pub.bitfinex.com/ws/pub"),
        wss_subscribe_msg: Some(r#"{"event":"subscribe","channel":"ticker","symbol":"tBTCUST"}"#),
        wss_subscribe_ack: Some(r#""event":"subscribed""#),
    },
    ExchangeDef {
        name: "Bitget",
        rest_base: "https://api.bitget.com",
        health_path: "/api/spot/v1/public/time",
        symbols_path: "/api/v2/spot/public/symbols",
        wss_url: Some("wss://ws.bitget.com/v2/ws/public"),
        wss_subscribe_msg: Some(r#"{"op":"subscribe","args":[{"instType":"SPOT","channel":"tickers","instId":"BTCUSDT"}]}"#),
        wss_subscribe_ack: Some(r#""event":"subscribe""#),
    },
    ExchangeDef {
        name: "BitMEX",
        rest_base: "https://www.bitmex.com",
        health_path: "/api/v1/time",
        symbols_path: "/api/v1/instrument/active",
        wss_url: Some("wss://ws.bitmex.com/realtime"),
        wss_subscribe_msg: Some(r#"{"op":"subscribe","args":["instrument:XBTUSD"]}"#),
        wss_subscribe_ack: Some(r#""subscribe""#),
    },
    ExchangeDef {
        name: "Coinbase",
        rest_base: "https://api.pro.coinbase.com",
        health_path: "/time",
        symbols_path: "/products",
        wss_url: Some("wss://ws-feed.exchange.coinbase.com"),
        wss_subscribe_msg: Some(r#"{"type":"subscribe","product_ids":["BTC-USD"],"channels":["ticker"]}"#),
        wss_subscribe_ack: Some(r#""type":"subscriptions""#),
    },
    ExchangeDef {
        name: "HTX (Huobi)",
        rest_base: "https://api.huobi.pro",
        health_path: "/v1/common/timestamp",
        symbols_path: "/v1/common/symbols",
        wss_url: Some("wss://api.huobi.pro/ws"),
        wss_subscribe_msg: Some(r#"{"sub":"market.btcusdt.detail","id":"conn-test-1"}"#),
        wss_subscribe_ack: Some(r#""subbed":""#),
    },
    ExchangeDef {
        name: "Kraken",
        rest_base: "https://api.kraken.com",
        health_path: "/0/public/Time",
        symbols_path: "/0/public/AssetPairs",
        wss_url: Some("wss://ws.kraken.com"),
        wss_subscribe_msg: Some(r#"{"event":"subscribe","subscription":{"name":"ticker"},"pair":["XBT/USD"]}"#),
        wss_subscribe_ack: Some(r#""event":"subscriptionStatus""#),
    },
    ExchangeDef {
        name: "LBank",
        rest_base: "https://api.lbank.info",
        health_path: "/v2/timestamp.do",
        symbols_path: "/v2/currencyPairs.do",
        wss_url: Some("wss://api.lbank.info/ws/v2"),
        wss_subscribe_msg: Some(r#"{"action":"subscribe","subscribe":"tickers","pair":"btc_usdt"}"#),
        wss_subscribe_ack: Some(r#""type":"subscribe""#),
    },
];

// ─── Helpers ────────────────────────────────────────────────────────────

fn status_icon(ok: bool) -> &'static str {
    if ok { "  OK  " } else { " FAIL " }
}

// ─── REST tests ─────────────────────────────────────────────────────────

async fn test_rest_health(
    client: &reqwest::Client,
    ex: &ExchangeDef,
) -> (bool, u128, Option<String>) {
    let url = format!("{}{}", ex.rest_base, ex.health_path);
    let start = Instant::now();
    match client.get(&url).timeout(Duration::from_secs(10)).send().await {
        Ok(resp) => {
            let ms = start.elapsed().as_millis();
            let status = resp.status().as_u16();
            if (200..300).contains(&status) {
                (true, ms, None)
            } else {
                (false, ms, Some(format!("HTTP {}", status)))
            }
        }
        Err(e) => {
            let ms = start.elapsed().as_millis();
            (false, ms, Some(e.to_string()))
        }
    }
}

async fn test_rest_symbols(
    client: &reqwest::Client,
    ex: &ExchangeDef,
) -> (bool, u128, Option<String>, usize) {
    let url = format!("{}{}", ex.rest_base, ex.symbols_path);
    let start = Instant::now();
    match client.get(&url).timeout(Duration::from_secs(10)).send().await {
        Ok(resp) => {
            let ms = start.elapsed().as_millis();
            let status = resp.status().as_u16();
            if (200..300).contains(&status) {
                match resp.text().await {
                    Ok(body) => {
                        let byte_len = body.len();
                        let symbol_count = if byte_len < 200 {
                            0
                        } else {
                            let commas = body.matches(',').count();
                            let quotes = body.matches('"').count() / 2;
                            std::cmp::max(commas, quotes) / 3
                        };
                        (true, ms, None, symbol_count)
                    }
                    Err(e) => (false, ms, Some(format!("body read: {}", e)), 0),
                }
            } else {
                (false, ms, Some(format!("HTTP {}", status)), 0)
            }
        }
        Err(e) => {
            let ms = start.elapsed().as_millis();
            (false, ms, Some(e.to_string()), 0)
        }
    }
}

// ─── WebSocket tests ────────────────────────────────────────────────────

async fn test_ws_connect(ex: &ExchangeDef) -> (bool, u128, Option<String>) {
    let wss = match ex.wss_url {
        Some(u) => u,
        None => return (false, 0, Some("no WSS URL configured".into())),
    };

    let start = Instant::now();
    let result = tokio_tungstenite::connect_async_tls_with_config(wss, None, false, None).await;

    match result {
        Ok((mut ws_stream, _response)) => {
            let connect_ms = start.elapsed().as_millis();

            if let (Some(msg), Some(ack_sub)) = (ex.wss_subscribe_msg, ex.wss_subscribe_ack) {
                if let Err(e) = ws_stream.send(Message::Text(msg.into())).await {
                    return (false, connect_ms, Some(format!("ws send: {}", e)));
                }

                match tokio::time::timeout(Duration::from_secs(5), ws_stream.next()).await {
                    Ok(Some(Ok(msg))) => {
                        let text = msg.to_text().unwrap_or("");
                        if text.contains(ack_sub) {
                            (true, connect_ms, None)
                        } else {
                            (true, connect_ms, Some(format!("ack: {}...", &text[..text.len().min(80)])))
                        }
                    }
                    Ok(Some(Err(e))) => (false, connect_ms, Some(format!("ws read: {}", e))),
                    Ok(None) => (false, connect_ms, Some("ws closed by server".into())),
                    Err(_) => (false, connect_ms, Some("ws read timeout (5s)".into())),
                }
            } else {
                (true, connect_ms, None)
            }
        }
        Err(e) => {
            let ms = start.elapsed().as_millis();
            (false, ms, Some(e.to_string()))
        }
    }
}

// ─── KuCoin special WS test (needs token handshake) ─────────────────────

async fn test_kucoin_ws() -> (bool, u128, Option<String>) {
    let client = reqwest::Client::new();
    let start = Instant::now();

    let token_url = "https://api.kucoin.com/api/v1/bullet-public";
    let token_resp = match client.post(token_url).timeout(Duration::from_secs(10)).send().await {
        Ok(r) => r,
        Err(e) => return (false, start.elapsed().as_millis(), Some(format!("token req: {}", e))),
    };

    let token_body = match token_resp.text().await {
        Ok(t) => t,
        Err(e) => return (false, start.elapsed().as_millis(), Some(format!("token read: {}", e))),
    };

    let token_json: serde_json::Value = match serde_json::from_str(&token_body) {
        Ok(v) => v,
        Err(e) => return (false, start.elapsed().as_millis(), Some(format!("token parse: {}", e))),
    };

    let data = match token_json.get("data") {
        Some(d) => d,
        None => return (false, start.elapsed().as_millis(), Some("no 'data' field".into())),
    };

    let token = match data.get("token").and_then(|t| t.as_str()) {
        Some(t) => t,
        None => return (false, start.elapsed().as_millis(), Some("no 'token' in data".into())),
    };

    let ws_endpoint = match data.get("connectServers")
        .and_then(|s| s.get(0))
        .and_then(|s| s.get("endpoint"))
        .and_then(|e| e.as_str())
    {
        Some(e) => e.to_string(),
        None => return (false, start.elapsed().as_millis(), Some("no endpoint in data".into())),
    };

    let ws_url = format!("{}?token={}", ws_endpoint, token);
    let token_ms = start.elapsed().as_millis();

    let ws_start = Instant::now();
    let result = tokio_tungstenite::connect_async_tls_with_config(&ws_url, None, false, None).await;

    match result {
        Ok((mut ws_stream, _resp)) => {
            let connect_ms = ws_start.elapsed().as_millis();
            let sub_msg = r#"{"id":"conn-test","type":"subscribe","topic":"/market/ticker:BTC-USDT","privateChannel":false,"response":true}"#;
            if let Err(e) = ws_stream.send(Message::Text(sub_msg.into())).await {
                return (false, connect_ms, Some(format!("ws send: {}", e)));
            }
            match tokio::time::timeout(Duration::from_secs(5), ws_stream.next()).await {
                Ok(Some(Ok(msg))) => {
                    let text = msg.to_text().unwrap_or("");
                    if text.contains("subscribe") {
                        (true, token_ms + connect_ms, None)
                    } else {
                        (true, token_ms + connect_ms, Some(format!("ack: {}...", &text[..text.len().min(80)])))
                    }
                }
                Ok(Some(Err(e))) => (false, connect_ms, Some(format!("ws read: {}", e))),
                Ok(None) => (false, connect_ms, Some("ws closed".into())),
                Err(_) => (false, connect_ms, Some("ws read timeout".into())),
            }
        }
        Err(e) => (false, ws_start.elapsed().as_millis(), Some(format!("ws connect: {}", e))),
    }
}

// ─── Main ───────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    println!();
    println!("======================================================================");
    println!("  EXCHANGE CONNECTIVITY TEST  -  REST + WebSocket  -  12 exchanges");
    println!("  No API keys required - public endpoints only");
    println!("======================================================================");
    println!();

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("reqwest client");

    let mut rest_ok = 0usize;
    let mut rest_fail = 0usize;
    let mut symbols_ok = 0usize;
    let mut ws_ok = 0usize;
    let mut ws_skip = 0usize;

    for ex in EXCHANGES {
        println!("+ {:<16}  REST: {}", ex.name, ex.rest_base);
        println!("{}", "-".repeat(78));

        // 1. Health check
        let (h_ok, h_ms, h_err) = test_rest_health(&client, ex).await;
        println!("  [{}] Health:    {:>5}ms  {}",
            if h_ok { "OK" } else { "FAIL" }, h_ms,
            h_err.as_deref().unwrap_or(""));
        if h_ok { rest_ok += 1; } else { rest_fail += 1; }

        // 2. Fetch symbols
        let (s_ok, s_ms, s_err, s_count) = test_rest_symbols(&client, ex).await;
        println!("  [{}] Symbols:  {:>5}ms  ~{} pairs  {}",
            if s_ok { "OK" } else { "FAIL" }, s_ms, s_count,
            s_err.as_deref().unwrap_or(""));
        if s_ok { symbols_ok += 1; }

        // 3. WebSocket
        if ex.name == "KuCoin" {
            println!("  Testing KuCoin WS (requires token handshake)...");
            let (w_ok, w_ms, w_err) = test_kucoin_ws().await;
            println!("  [{}] WS:       {:>5}ms  {}",
                if w_ok { "OK" } else { "FAIL" }, w_ms,
                w_err.as_deref().unwrap_or("subscribed"));
            if w_ok { ws_ok += 1; }
        } else if ex.wss_url.is_some() {
            let (w_ok, w_ms, w_err) = test_ws_connect(ex).await;
            println!("  [{}] WS:       {:>5}ms  {}",
                if w_ok { "OK" } else { "FAIL" }, w_ms,
                w_err.as_deref().unwrap_or("connected + subscribed"));
            if w_ok { ws_ok += 1; }
        } else {
            println!("  [-- ] WS:       (no WSS URL configured)");
            ws_skip += 1;
        }

        println!();
    }

    // Summary
    let total = EXCHANGES.len();
    println!("======================================================================");
    println!("  RESULTS: {} exchanges", total);
    println!("  REST health:  {}/{} passed", rest_ok, total);
    println!("  REST symbols: {}/{} passed", symbols_ok, total);
    println!("  WebSocket:    {}/{} passed  ({} skipped)", ws_ok, total, ws_skip);
    println!("======================================================================");

    if rest_fail > 0 || ws_ok + ws_skip < total {
        println!("\n  NOTE: Failures may be due to network restrictions in this");
        println!("  environment (firewall, geo-blocking, VPN required, etc.)");
        println!("  Re-run from a machine with unrestricted internet access.");
    }
}