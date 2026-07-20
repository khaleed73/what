//! ═══════════════════════════════════════════════════════════════════════════════
//! PIPELINE LATENCY BENCHMARK — Full End-to-End Timing Across All 12 Exchanges
//! ═══════════════════════════════════════════════════════════════════════════════
//!
//! Measures MICROSECOND-LEVEL latency for each pipeline stage:

#![allow(dead_code)]
//!
//!   Stage 0: HEALTH CHECK     — REST connectivity to each exchange
//!   Stage 1: ORDERBOOK FETCH  — REST orderbook download per (exchange, token)
//!   Stage 2: ARENA UPDATE     — Atomic price matrix write (hot-path only)
//!   Stage 3: CROSS-EXCH BUILD — build_cross_exchange_targets()
//!   Stage 4: TRIANGULAR BUILD — build_triangular_loops()
//!   Stage 5: STRATEGY SCAN    — evaluate_tick() across all (exchange, token) pairs
//!   Stage 6: RISK GATE        — pre_trade_check() 14-layer check
//!   Stage 7: CROSS-EXCH EXEC  — blast_arbitrage_legs() (paper)
//!   Stage 8: TRIANGULAR EXEC  — blast_triangular_legs() (paper)
//!   Stage 9: FULL PIPELINE    — End-to-end: new price → signal → risk → execute
//!
//! Also runs an in-memory micro-benchmark (no network) to measure
//! the pure computational pipeline latency (arena→strategy→risk→execute)
//! without network noise, repeated 10,000 times for P50/P95/P99.
//!
//! No real API keys needed — only public REST endpoints are hit.

use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Instant;

use rust_decimal::prelude::ToPrimitive;
use rust_decimal::Decimal;
use rust_decimal_macros::dec;
use tokio::sync::Mutex;

use rust_hft_arb::exchange::config::ExchangeConfig;
use rust_hft_arb::exchange::exchange_trait::Exchange;
use rust_hft_arb::exchange::{
    bitfinex::BitfinexClient, bitget::BitgetClient, bitmex::BitmexClient,
    binance::BinanceClient, bybit::BybitClient, coinbase::CoinbaseClient,
    gateio::GateioClient, htx::HtxClient, kraken::KrakenClient,
    kucoin::KucoinClient, lbank::LbankClient, okx::OkxClient,
};
use rust_hft_arb::execution::{
    HighFrequencyExecutionEngine, OrderIntent, OrderPipeline, PaperExecutionPipeline,
};

use rust_hft_arb::protections::RiskManager;
use rust_hft_arb::stablecoin::{StablecoinConfig, StablecoinMonitor};
use rust_hft_arb::strategies::{ArbitrageSignal, MarketArena};
use rust_hft_arb::configs::ValidatedRiskConfig;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const DUMMY_KEY: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const DUMMY_SECRET: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

const NUM_EXCHANGES: usize = 12;
const NUM_TOKENS: usize = 3;
const TOKEN_BTC: usize = 0;
const TOKEN_ETH: usize = 1;
const TOKEN_SOL: usize = 2;
const FP_SCALE: u64 = 10_000;

const TOKEN_SYMBOLS: [&str; NUM_TOKENS] = ["BTC/USDT", "ETH/USDT", "SOL/USDT"];
const TOKEN_NAMES: [&str; NUM_TOKENS] = ["BTC", "ETH", "SOL"];

struct ExchangeMeta {
    id: usize,
    name: &'static str,
    base_url: &'static str,
    symbol_overrides: [Option<&'static str>; NUM_TOKENS],
}

const EXCHANGES: [ExchangeMeta; NUM_EXCHANGES] = [
    ExchangeMeta { id: 0,  name: "Binance",  base_url: "https://api.binance.com",           symbol_overrides: [None, None, None] },
    ExchangeMeta { id: 1,  name: "Bybit",    base_url: "https://api.bybit.com",             symbol_overrides: [None, None, None] },
    ExchangeMeta { id: 2,  name: "OKX",      base_url: "https://www.okx.com",               symbol_overrides: [None, None, None] },
    ExchangeMeta { id: 3,  name: "GateIO",   base_url: "https://api.gateio.ws",             symbol_overrides: [None, None, None] },
    ExchangeMeta { id: 4,  name: "KuCoin",   base_url: "https://api.kucoin.com",            symbol_overrides: [None, None, None] },
    ExchangeMeta { id: 5,  name: "Bitfinex", base_url: "https://api.bitfinex.com",          symbol_overrides: [Some("BTC/USD"), Some("ETH/USD"), Some("SOL/USD")] },
    ExchangeMeta { id: 6,  name: "Bitget",   base_url: "https://api.bitget.com",            symbol_overrides: [None, None, None] },
    ExchangeMeta { id: 7,  name: "BitMEX",   base_url: "https://www.bitmex.com",            symbol_overrides: [Some("XBTUSD"), Some("ETHUSD"), None] },
    ExchangeMeta { id: 8,  name: "Coinbase", base_url: "https://api.exchange.coinbase.com", symbol_overrides: [Some("BTC/USD"), Some("ETH/USD"), Some("SOL/USD")] },
    ExchangeMeta { id: 9,  name: "HTX",      base_url: "https://api.huobi.pro",             symbol_overrides: [None, None, None] },
    ExchangeMeta { id: 10, name: "Kraken",   base_url: "https://api.kraken.com",            symbol_overrides: [Some("XBT/USDT"), Some("ETH/USDT"), Some("SOL/USDT")] },
    ExchangeMeta { id: 11, name: "LBank",    base_url: "https://api.lbank.info",            symbol_overrides: [None, None, None] },
];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn dummy_config(base_url: &str) -> ExchangeConfig {
    ExchangeConfig::new(DUMMY_KEY, DUMMY_SECRET, base_url)
}

fn decimal_to_fp(d: Decimal) -> u64 {
    let scaled = d * Decimal::from(FP_SCALE);
    scaled.to_u64().unwrap_or(0)
}

fn fp_to_display(fp: u64) -> String {
    let whole = fp / FP_SCALE;
    let frac = fp % FP_SCALE;
    format!("{}.{:04}", whole, frac)
}

fn exch_name(id: u16) -> &'static str {
    EXCHANGES.get(id as usize).map(|e| e.name).unwrap_or("???")
}

fn tok_name(id: u16) -> &'static str {
    TOKEN_NAMES.get(id as usize).copied().unwrap_or("???")
}

fn book_to_fp(book: &rust_hft_arb::exchange::types::OrderBookSnapshot) -> (u64, u64) {
    let bid = book.bids.first().map(|l| decimal_to_fp(l.price)).unwrap_or(0);
    let ask = book.asks.first().map(|l| decimal_to_fp(l.price)).unwrap_or(0);
    (bid, ask)
}

/// Compute percentile from a sorted slice of durations.
fn percentile(sorted: &[u128], pct: f64) -> u128 {
    if sorted.is_empty() { return 0; }
    let idx = ((pct / 100.0) * (sorted.len() - 1) as f64).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

fn create_exchange_client(meta: &ExchangeMeta) -> anyhow::Result<Box<dyn Exchange>> {
    let cfg = dummy_config(meta.base_url);
    let name = meta.name.to_string();
    Ok(match meta.id {
        0  => Box::new(BinanceClient::new(name, cfg)?),
        1  => Box::new(BybitClient::new(name, cfg)?),
        2  => Box::new(OkxClient::new(name, cfg)?),
        3  => Box::new(GateioClient::new(name, cfg)?),
        4  => Box::new(KucoinClient::new(name, cfg)?),
        5  => Box::new(BitfinexClient::new(name, cfg)?),
        6  => Box::new(BitgetClient::new(name, cfg)?),
        7  => Box::new(BitmexClient::new(name, cfg)?),
        8  => Box::new(CoinbaseClient::new(name, cfg)?),
        9  => Box::new(HtxClient::new(name, cfg)?),
        10 => Box::new(KrakenClient::new(name, cfg)?),
        11 => Box::new(LbankClient::new(name, cfg)?),
        _  => anyhow::bail!("unknown exchange id {}", meta.id),
    })
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    println!("\n{}", "═".repeat(78));
    println!("  PIPELINE LATENCY BENCHMARK — ALL 12 EXCHANGES");
    println!("  Datafeed → Arena → Strategy → Risk Gate → Execution");
    println!("  Microsecond-precision timing per stage");
    println!("{}\n", "═".repeat(78));

    // ======================================================================
    // STAGE 0: HEALTH CHECK — measure REST connectivity latency per exchange
    // ======================================================================
    println!("┌─ STAGE 0: HEALTH CHECK (REST Connectivity) ─────────────────────────┐");
    println!("│ {:<12} │ {:>10} │ {:>6} │", "Exchange", "Latency", "Status");
    println!("├──────────────┼────────────┼────────┤");

    let mut clients: Vec<Option<Box<dyn Exchange>>> = Vec::with_capacity(NUM_EXCHANGES);
    let mut health_ok = [false; NUM_EXCHANGES];
    let mut health_latencies_us: Vec<u128> = Vec::new();

    for (i, meta) in EXCHANGES.iter().enumerate() {
        let client = match create_exchange_client(meta) {
            Ok(c) => c,
            Err(e) => {
                println!("│ {:<12} │ {:>10} │  ERR  │", meta.name, format!("N/A: {}", e));
                clients.push(None);
                continue;
            }
        };

        let t = Instant::now();
        let result = client.health_check().await;
        let us = t.elapsed().as_micros();

        health_ok[i] = result.is_ok();
        if result.is_ok() {
            health_latencies_us.push(us);
            println!("│ {:<12} │ {:>8} μs │  OK   │", meta.name, us);
        } else {
            println!("│ {:<12} │ {:>8} μs │ FAIL  │", meta.name, us);
        }
        clients.push(Some(client));

        if i < NUM_EXCHANGES - 1 {
            tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
        }
    }

    health_latencies_us.sort();
    let h_p50 = percentile(&health_latencies_us, 50.0);
    let h_p95 = percentile(&health_latencies_us, 95.0);
    let h_p99 = percentile(&health_latencies_us, 99.0);
    let h_pass = health_ok.iter().filter(|&&x| x).count();
    println!("├──────────────┼────────────┼────────┤");
    println!("│ {:<12} │ P50={:>5}μs │ {}/12  │", "MEDIAN", h_p50, h_pass);
    println!("│ {:<12} │ P95={:>5}μs │        │", "", h_p95);
    println!("│ {:<12} │ P99={:>5}μs │        │", "", h_p99);
    println!("└──────────────┴────────────┴────────┘");

    // ======================================================================
    // STAGE 1: ORDERBOOK FETCH — measure per-(exchange, token) REST latency
    // ======================================================================
    println!("\n┌─ STAGE 1: ORDERBOOK FETCH (REST) ───────────────────────────────────┐");
    println!("│ {:<12} │ {:<6} │ {:>10} │ {:>6} │", "Exchange", "Token", "Latency", "Levels");
    println!("├──────────────┼────────┼────────────┼────────┤");

    let mut prices: [[(u64, u64); NUM_TOKENS]; NUM_EXCHANGES] = [[(0, 0); NUM_TOKENS]; NUM_EXCHANGES];
    let mut book_ok: [[bool; NUM_TOKENS]; NUM_EXCHANGES] = [[false; NUM_TOKENS]; NUM_EXCHANGES];
    let mut ob_latencies_us: Vec<u128> = Vec::new();

    for (i, meta) in EXCHANGES.iter().enumerate() {
        let client = match &clients[i] {
            Some(c) => c,
            None => continue,
        };
        if !health_ok[i] { continue; }

        for (t, tok) in TOKEN_NAMES.iter().enumerate() {
            let symbol = meta.symbol_overrides[t].unwrap_or(TOKEN_SYMBOLS[t]);

            let t0 = Instant::now();
            match client.fetch_order_book(symbol, 5).await {
                Ok(book) => {
                    let us = t0.elapsed().as_micros();
                    let (bid, ask) = book_to_fp(&book);
                    let levels = book.bids.len().min(book.asks.len());

                    if bid > 0 && ask > 0 {
                        prices[i][t] = (bid, ask);
                        book_ok[i][t] = true;
                        ob_latencies_us.push(us);
                        let spread = ((ask - bid) * 10_000) / ask;
                        println!("│ {:<12} │ {:<6} │ {:>8} μs │ {:>4}L  │ spread={}bps",
                            meta.name, tok, us, levels, spread);
                    } else {
                        println!("│ {:<12} │ {:<6} │ {:>8} μs │ EMPTY │", meta.name, tok, us);
                    }
                }
                Err(_e) => {
                    let us = t0.elapsed().as_micros();
                    println!("│ {:<12} │ {:<6} │ {:>8} μs │ ERR   │", meta.name, tok, us);
                }
            }

            tokio::time::sleep(tokio::time::Duration::from_millis(250)).await;
        }
    }

    ob_latencies_us.sort();
    let ob_p50 = percentile(&ob_latencies_us, 50.0);
    let ob_p95 = percentile(&ob_latencies_us, 95.0);
    let ob_p99 = percentile(&ob_latencies_us, 99.0);
    println!("├──────────────┼────────┼────────────┼────────┤");
    println!("│ {:<18} │ P50={:>6}μs │        │", "ORDERBOOK MEDIAN", ob_p50);
    println!("│ {:<18} │ P95={:>6}μs │        │", "", ob_p95);
    println!("│ {:<18} │ P99={:>6}μs │        │", "", ob_p99);
    println!("│ {:<18} │ n={:>8}   │        │", "samples", ob_latencies_us.len());
    println!("└──────────────┴────────┴────────────┴────────┘");

    // ======================================================================
    // STAGE 2: ARENA UPDATE — atomic price matrix write (HOT PATH)
    // ======================================================================
    println!("\n┌─ STAGE 2: ARENA UPDATE (Atomic Price Write) ───────────────────────┐");

    let arena = Arc::new(MarketArena::new(NUM_EXCHANGES, NUM_TOKENS));
    let mut arena_update_us: Vec<u128> = Vec::new();

    for i in 0..NUM_EXCHANGES {
        for t in 0..NUM_TOKENS {
            let (bid, ask) = prices[i][t];
            if bid == 0 || ask == 0 { continue; }

            let t0 = Instant::now();
            arena.update_price(i, t, bid, ask);
            let us = t0.elapsed().as_micros();
            arena_update_us.push(us);
        }
    }

    arena_update_us.sort();
    let au_p50 = percentile(&arena_update_us, 50.0);
    let au_p95 = percentile(&arena_update_us, 95.0);
    let au_p99 = percentile(&arena_update_us, 99.0);
    let au_max = *arena_update_us.last().unwrap_or(&0);
    println!("│  {} price updates measured", arena_update_us.len());
    println!("│  P50: {:>6} μs   P95: {:>6} μs   P99: {:>6} μs   MAX: {:>6} μs",
        au_p50, au_p95, au_p99, au_max);
    println!("└──────────────────────────────────────────────────────────────────────┘");

    // ======================================================================
    // STAGE 3: CROSS-EXCHANGE TARGETS BUILD
    // ======================================================================
    println!("\n┌─ STAGE 3: CROSS-EXCHANGE TARGETS BUILD ────────────────────────────┐");

    let t0 = Instant::now();
    arena.build_cross_exchange_targets().await;
    let cross_build_us = t0.elapsed().as_micros();

    let ct = arena.cross_targets.read().await;
    let cross_count = ct.iter().filter(|t| t.shared_count >= 2).count();
    drop(ct);

    println!("│  Build time: {:>8} μs   ({} tokens on >= 2 exchanges)", cross_build_us, cross_count);
    println!("└──────────────────────────────────────────────────────────────────────┘");

    // ======================================================================
    // STAGE 4: TRIANGULAR LOOPS BUILD
    // ======================================================================
    println!("\n┌─ STAGE 4: TRIANGULAR LOOPS BUILD ──────────────────────────────────┐");

    let mut exchange_pairs: HashMap<u16, Vec<(u16, u16)>> = HashMap::new();
    let tri_cycle = vec![
        (TOKEN_BTC as u16, TOKEN_ETH as u16),
        (TOKEN_ETH as u16, TOKEN_SOL as u16),
        (TOKEN_SOL as u16, TOKEN_BTC as u16),
    ];
    for i in 0..NUM_EXCHANGES {
        if book_ok[i][TOKEN_BTC] && book_ok[i][TOKEN_ETH] && book_ok[i][TOKEN_SOL] {
            exchange_pairs.insert(i as u16, tri_cycle.clone());
        }
    }

    let t0 = Instant::now();
    arena.build_triangular_loops(&exchange_pairs).await;
    let tri_build_us = t0.elapsed().as_micros();

    let tm = arena.tri_loops.read().await;
    let total_loops: usize = tm.values().map(|v| v.len()).sum();
    drop(tm);

    println!("│  Build time: {:>8} μs   ({} loops across {} exchanges)",
        tri_build_us, total_loops, exchange_pairs.len());
    println!("└──────────────────────────────────────────────────────────────────────┘");

    // ======================================================================
    // STAGE 5: STRATEGY SCAN — evaluate_tick() across all pairs
    // ======================================================================
    println!("\n┌─ STAGE 5: STRATEGY SCAN (evaluate_tick) ───────────────────────────┐");

    let mut all_signals: Vec<ArbitrageSignal> = Vec::new();

    // Measure per-pair latency
    let mut scan_latencies_us: Vec<u128> = Vec::new();
    for exch_id in 0..NUM_EXCHANGES {
        for token_id in 0..NUM_TOKENS {
            let t0 = Instant::now();
            let sigs = arena.evaluate_tick(exch_id, token_id, 0, 0);
            let us = t0.elapsed().as_micros();
            scan_latencies_us.push(us);
            all_signals.extend(sigs);
        }
    }

    scan_latencies_us.sort();
    let sc_p50 = percentile(&scan_latencies_us, 50.0);
    let sc_p95 = percentile(&scan_latencies_us, 95.0);
    let sc_p99 = percentile(&scan_latencies_us, 99.0);

    let cross_count = all_signals.iter()
        .filter(|s| matches!(s, ArbitrageSignal::CrossExchange { .. })).count();
    let tri_count = all_signals.iter()
        .filter(|s| matches!(s, ArbitrageSignal::Triangular { .. })).count();

    println!("│  {} evaluate_tick() calls ({} exchanges x {} tokens)", scan_latencies_us.len(), NUM_EXCHANGES, NUM_TOKENS);
    println!("│  Per-tick P50: {:>5} μs   P95: {:>5} μs   P99: {:>5} μs", sc_p50, sc_p95, sc_p99);
    println!("│  Full scan (all pairs): {:>6} μs", scan_latencies_us.iter().sum::<u128>());
    println!("│  Signals found: {} (cross: {}, triangular: {})", all_signals.len(), cross_count, tri_count);

    // Inject synthetic signals if no real ones
    if all_signals.is_empty() {
        println!("│  [Injecting synthetic spread to measure downstream stages]");
        inject_synthetic_signals(&arena, &mut all_signals, &prices, &book_ok, &exchange_pairs).await;
    }

    println!("└──────────────────────────────────────────────────────────────────────┘");

    // ======================================================================
    // STAGE 6: RISK GATE — 14-layer pre_trade_check
    // ======================================================================
    println!("\n┌─ STAGE 6: RISK GATE (pre_trade_check — 14 layers) ─────────────────┐");

    let risk_config = ValidatedRiskConfig {
        min_net_profit_pct: dec!(0.0),
        max_equity_staleness_seconds: 300,
        absolute_hard_loss_cap: dec!(10000.0),
        pct_hard_loss_cap: dec!(50.0),
        max_drawdown_pct: dec!(25.0),
        max_total_exposure_pct: dec!(100.0),
        max_single_position_pct: dec!(50.0),
        exchange_failure_threshold: 5,
        exchange_pause_duration_seconds: 60,
        stablecoin_depeg_threshold: dec!(5.0),
        daily_loss_limit_usd: dec!(100.0),
    };
    let risk_manager = Arc::new(RiskManager::new(risk_config));
    risk_manager.update_equity(10_000_000_000);
    risk_manager.touch_network_check();

    let mut risk_latencies_us: Vec<u128> = Vec::new();
    let mut passed: Vec<ArbitrageSignal> = Vec::new();
    let mut blocked = 0usize;

    for sig in &all_signals {
        let t0 = Instant::now();
        let (pbps, eid) = match sig {
            ArbitrageSignal::CrossExchange { spread_bps, buy_exchange, .. } => (*spread_bps, *buy_exchange),
            ArbitrageSignal::Triangular { profit_bps, exchange_id, .. } => (*profit_bps, *exchange_id),
            _ => (0, 0),
        };
        match risk_manager.pre_trade_check(pbps, 1_000_000, 10_000_000_000, eid) {
            Ok(()) => {
                let us = t0.elapsed().as_micros();
                risk_latencies_us.push(us);
                passed.push(sig.clone());
            }
            Err(_) => { blocked += 1; }
        }
    }

    risk_latencies_us.sort();
    let rg_p50 = percentile(&risk_latencies_us, 50.0);
    let rg_p95 = percentile(&risk_latencies_us, 95.0);
    let rg_p99 = percentile(&risk_latencies_us, 99.0);

    println!("│  {} signals evaluated", all_signals.len());
    println!("│  Passed: {}   Blocked: {}", passed.len(), blocked);
    println!("│  Per-check P50: {:>5} μs   P95: {:>5} μs   P99: {:>5} μs", rg_p50, rg_p95, rg_p99);
    println!("└──────────────────────────────────────────────────────────────────────┘");

    // ======================================================================
    // STAGES 7 & 8: EXECUTION — blast_arbitrage_legs + blast_triangular_legs
    // ======================================================================
    println!("\n┌─ STAGE 7 & 8: EXECUTION (Paper Pipeline Blast) ────────────────────┐");

    let paper_balance = Arc::new(Mutex::new(dec!(10000.00)));
    let paper_pipeline: Arc<dyn OrderPipeline> = Arc::new(PaperExecutionPipeline::new(Arc::clone(&paper_balance)));
    let real_pipeline: Arc<dyn OrderPipeline> = Arc::new(PaperExecutionPipeline::new(Arc::clone(&paper_balance)));
    let depeg_circuit = Arc::new(StablecoinMonitor::new(StablecoinConfig::default()));
    let engine = Arc::new(HighFrequencyExecutionEngine::new(
        Arc::clone(&risk_manager),
        Arc::clone(&depeg_circuit),
        Arc::clone(&paper_pipeline),
        real_pipeline,
        true, // paper mode
    ));

    let mut cross_exec_us: Vec<u128> = Vec::new();
    let mut tri_exec_us: Vec<u128> = Vec::new();
    let mut cross_fired = 0u32;
    let mut tri_fired = 0u32;

    for sig in passed.iter() {
        match sig {
            ArbitrageSignal::CrossExchange { buy_exchange, sell_exchange, token_id, spread_bps } => {
                if cross_fired >= 3 { continue; }
                cross_fired += 1;
                let sym = format!("{}USDT", tok_name(*token_id));
                let buy_idx = arena.get_index(*buy_exchange as usize, *token_id as usize);
                let sell_idx = arena.get_index(*sell_exchange as usize, *token_id as usize);
                let buy_price = Decimal::from(arena.ask_prices[buy_idx].load(Ordering::Acquire)) / Decimal::from(FP_SCALE);
                let sell_price = Decimal::from(arena.bid_prices[sell_idx].load(Ordering::Acquire)) / Decimal::from(FP_SCALE);

                let leg_a = OrderIntent { exchange_id: *buy_exchange, token_id: *token_id, qty: dec!(0.001), price: buy_price, is_buy: true, symbol: sym.clone() };
                let leg_b = OrderIntent { exchange_id: *sell_exchange, token_id: *token_id, qty: dec!(0.001), price: sell_price, is_buy: false, symbol: sym };

                let t0 = Instant::now();
                let _ = engine.blast_arbitrage_legs(leg_a, leg_b, *spread_bps, 10_000_000_000).await;
                cross_exec_us.push(t0.elapsed().as_micros());
            }
            ArbitrageSignal::Triangular { exchange_id, token_a, token_b, token_c, profit_bps } => {
                if tri_fired >= 3 { continue; }
                tri_fired += 1;
                let idx_a = arena.get_index(*exchange_id as usize, *token_a as usize);
                let idx_b = arena.get_index(*exchange_id as usize, *token_b as usize);
                let idx_c = arena.get_index(*exchange_id as usize, *token_c as usize);
                let pa = Decimal::from(arena.ask_prices[idx_a].load(Ordering::Acquire)) / Decimal::from(FP_SCALE);
                let pb = Decimal::from(arena.ask_prices[idx_b].load(Ordering::Acquire)) / Decimal::from(FP_SCALE);
                let pc = Decimal::from(arena.ask_prices[idx_c].load(Ordering::Acquire)) / Decimal::from(FP_SCALE);

                let legs = [
                    OrderIntent { exchange_id: *exchange_id, token_id: *token_a, qty: dec!(0.01), price: pa, is_buy: true, symbol: format!("{}USDT", tok_name(*token_a)) },
                    OrderIntent { exchange_id: *exchange_id, token_id: *token_b, qty: dec!(0.01), price: pb, is_buy: true, symbol: format!("{}USDT", tok_name(*token_b)) },
                    OrderIntent { exchange_id: *exchange_id, token_id: *token_c, qty: dec!(0.01), price: pc, is_buy: true, symbol: format!("{}USDT", tok_name(*token_c)) },
                ];

                let t0 = Instant::now();
                let _ = engine.blast_triangular_legs(legs, *profit_bps, 10_000_000_000).await;
                tri_exec_us.push(t0.elapsed().as_micros());
            }
            _ => {}
        }
    }

    cross_exec_us.sort();
    tri_exec_us.sort();

    if !cross_exec_us.is_empty() {
        println!("│  Cross-Exchange blast_arbitrage_legs ({} fires):", cross_exec_us.len());
        println!("│    P50: {:>6} μs   P95: {:>6} μs   P99: {:>6} μs",
            percentile(&cross_exec_us, 50.0),
            percentile(&cross_exec_us, 95.0),
            percentile(&cross_exec_us, 99.0));
    }
    if !tri_exec_us.is_empty() {
        println!("│  Triangular blast_triangular_legs ({} fires):", tri_exec_us.len());
        println!("│    P50: {:>6} μs   P95: {:>6} μs   P99: {:>6} μs",
            percentile(&tri_exec_us, 50.0),
            percentile(&tri_exec_us, 95.0),
            percentile(&tri_exec_us, 99.0));
    }
    if cross_exec_us.is_empty() && tri_exec_us.is_empty() {
        println!("│  No execution samples (no signals passed risk gate)");
    }
    println!("└──────────────────────────────────────────────────────────────────────┘");

    // ======================================================================
    // STAGE 9: FULL PIPELINE — in-memory micro-benchmark (10,000 iterations)
    // ======================================================================
    println!("\n┌─ STAGE 9: FULL PIPELINE MICRO-BENCHMARK (10,000 iterations) ───────┐");
    println!("│  Measures: update_price → evaluate_tick → pre_trade_check           │");
    println!("│  (Pure computation, no network I/O)                                │");
    println!("├──────────────────────────────────────────────────────────────────────┤");

    const ITERATIONS: usize = 10_000;
    let mut full_pipeline_us: Vec<u128> = Vec::with_capacity(ITERATIONS);

    // Use token 0 (BTC) on exchange 0 — just cycle through exchanges
    for iter in 0..ITERATIONS {
        let exch = iter % NUM_EXCHANGES;
        let tok = iter % NUM_TOKENS;
        let (bid, ask) = prices[exch][tok];
        if bid == 0 || ask == 0 { continue; }

        // Slightly perturb to prevent caching effects
        let noisy_bid = bid + ((iter as u64) % 100);
        let noisy_ask = ask + ((iter as u64) % 100) + 50;

        let t0 = Instant::now();

        // Stage A: Arena update
        arena.update_price(exch, tok, noisy_bid, noisy_ask);

        // Stage B: Strategy scan (single tick)
        let sigs = arena.evaluate_tick(exch, tok, 0, 0);

        // Stage C: Risk gate for each signal
        for sig in &sigs {
            let (pbps, eid) = match sig {
                ArbitrageSignal::CrossExchange { spread_bps, buy_exchange, .. } => (*spread_bps, *buy_exchange),
                ArbitrageSignal::Triangular { profit_bps, exchange_id, .. } => (*profit_bps, *exchange_id),
                _ => (0, 0),
            };
            let _ = risk_manager.pre_trade_check(pbps, 1_000_000, 10_000_000_000, eid);
        }

        full_pipeline_us.push(t0.elapsed().as_micros());
    }

    full_pipeline_us.sort();
    let fp_p50 = percentile(&full_pipeline_us, 50.0);
    let fp_p95 = percentile(&full_pipeline_us, 95.0);
    let fp_p99 = percentile(&full_pipeline_us, 99.0);
    let fp_max = *full_pipeline_us.last().unwrap_or(&0);
    let fp_total = full_pipeline_us.iter().sum::<u128>();

    println!("│  Iterations:        {:>8}                                       │", full_pipeline_us.len());
    println!("│  P50 (median):      {:>6} μs                                        │", fp_p50);
    println!("│  P95:               {:>6} μs                                        │", fp_p95);
    println!("│  P99:               {:>6} μs                                        │", fp_p99);
    println!("│  MAX:               {:>6} μs                                        │", fp_max);
    println!("│  Total:             {:>6} ms  ({:.1}M ticks/sec)                   │",
        fp_total / 1000,
        if fp_total > 0 { full_pipeline_us.len() as f64 / (fp_total as f64 / 1_000_000.0) } else { 0.0 });
    println!("└──────────────────────────────────────────────────────────────────────┘");

    // ======================================================================
    // GRAND SUMMARY
    // ======================================================================
    println!("\n{}", "═".repeat(78));
    println!("  LATENCY SUMMARY — PIPELINE STAGES");
    println!("{}", "═".repeat(78));
    println!("  ┌──────────────────────────────────┬──────────┬──────────┬──────────┬──────────┐");
    println!("  │ Stage                             │   P50    │   P95    │   P99    │   MAX    │");
    println!("  ├──────────────────────────────────┼──────────┼──────────┼──────────┼──────────┤");
    println!("  │ 0. Health Check (REST)            │ {:>6} μs │ {:>6} μs │ {:>6} μs │ {:>6} μs │", h_p50, h_p95, h_p99, percentile(&health_latencies_us, 100.0));
    println!("  │ 1. Orderbook Fetch (REST)         │ {:>6} μs │ {:>6} μs │ {:>6} μs │ {:>6} μs │", ob_p50, ob_p95, ob_p99, percentile(&ob_latencies_us, 100.0));
    println!("  │ 2. Arena Update (atomic write)    │ {:>6} μs │ {:>6} μs │ {:>6} μs │ {:>6} μs │", au_p50, au_p95, au_p99, au_max);
    println!("  │ 3. Cross-Exchange Targets Build   │ {:>6} μs │    —     │    —     │    —     │", cross_build_us);
    println!("  │ 4. Triangular Loops Build         │ {:>6} μs │    —     │    —     │    —     │", tri_build_us);
    println!("  │ 5. Strategy evaluate_tick()       │ {:>6} μs │ {:>6} μs │ {:>6} μs │ {:>6} μs │", sc_p50, sc_p95, sc_p99, percentile(&scan_latencies_us, 100.0));
    println!("  │ 6. Risk Gate pre_trade_check()    │ {:>6} μs │ {:>6} μs │ {:>6} μs │ {:>6} μs │", rg_p50, rg_p95, rg_p99, percentile(&risk_latencies_us, 100.0));

    if !cross_exec_us.is_empty() {
        println!("  │ 7. Cross-Exch Blast (paper)       │ {:>6} μs │ {:>6} μs │ {:>6} μs │ {:>6} μs │",
            percentile(&cross_exec_us, 50.0), percentile(&cross_exec_us, 95.0),
            percentile(&cross_exec_us, 99.0), *cross_exec_us.last().unwrap_or(&0));
    }
    if !tri_exec_us.is_empty() {
        println!("  │ 8. Triangular Blast (paper)       │ {:>6} μs │ {:>6} μs │ {:>6} μs │ {:>6} μs │",
            percentile(&tri_exec_us, 50.0), percentile(&tri_exec_us, 95.0),
            percentile(&tri_exec_us, 99.0), *tri_exec_us.last().unwrap_or(&0));
    }

    println!("  ├──────────────────────────────────┼──────────┴──────────┴──────────┴──────────┤");
    println!("  │ 9. FULL PIPELINE (in-memory)     │ P50={:>5}μs  P95={:>5}μs  P99={:>5}μs  MAX={:>5}μs │",
        fp_p50, fp_p95, fp_p99, fp_max);
    println!("  │    Throughput: {:.1}M ticks/sec                                    │",
        if fp_total > 0 { full_pipeline_us.len() as f64 / (fp_total as f64 / 1_000_000.0) } else { 0.0 });
    println!("  └──────────────────────────────────┴────────────────────────────────────────┘");

    // Hot-path breakdown (no network)
    println!("\n  ┌─ HOT-PATH BREAKDOWN (arena → strategy → risk, no network) ──────┐");
    let hot_p50 = au_p50 + sc_p50 + rg_p50;
    let hot_p95 = au_p95 + sc_p95 + rg_p95;
    let hot_p99 = au_p99 + sc_p99 + rg_p99;
    println!("  │  Combined P50: {:>6} μs   P95: {:>6} μs   P99: {:>6} μs          │", hot_p50, hot_p95, hot_p99);
    println!("  │  (Arena + Strategy + Risk — the decision loop)                    │");
    println!("  └──────────────────────────────────────────────────────────────────┘");

    println!("\n{}", "═".repeat(78));

    // Production-readiness assessment
    println!("\n  PRODUCTION LATENCY ASSESSMENT:");
    println!("  ──────────────────────────────");

    let hot_path_ok = hot_p50 < 100; // sub-100μs hot path
    let throughput_ok = fp_total > 0 && (full_pipeline_us.len() as f64 / (fp_total as f64 / 1_000_000.0)) > 100_000.0;
    let ob_ok = ob_p95 < 500_000; // sub-500ms orderbook fetch

    println!("  {:>30}  {}", "Hot-path P50 < 100 μs:", if hot_path_ok { "PASS" } else { "WARN" });
    println!("  {:>30}  {} ({:.1}M ticks/sec)", "Throughput > 100K ticks/sec:",
        if throughput_ok { "PASS" } else { "WARN" },
        if fp_total > 0 { full_pipeline_us.len() as f64 / (fp_total as f64 / 1_000_000.0) } else { 0.0 });
    println!("  {:>30}  {}", "Orderbook P95 < 500 ms:", if ob_ok { "PASS" } else { "WARN (network-dependent)" });
    println!("  {:>30}  {}/12", "Exchanges reachable:", h_pass);
    println!("\n{}", "═".repeat(78));

    Ok(())
}

// ---------------------------------------------------------------------------
// Inject synthetic signals for benchmarking downstream stages
// ---------------------------------------------------------------------------

async fn inject_synthetic_signals(
    arena: &Arc<MarketArena>,
    all_signals: &mut Vec<ArbitrageSignal>,
    prices: &[[(u64, u64); NUM_TOKENS]; NUM_EXCHANGES],
    book_ok: &[[bool; NUM_TOKENS]; NUM_EXCHANGES],
    exchange_pairs: &HashMap<u16, Vec<(u16, u16)>>,
) {
    // Find two exchanges with BTC data for cross-exchange
    let mut exch_a: Option<usize> = None;
    let mut exch_b: Option<usize> = None;
    for i in 0..NUM_EXCHANGES {
        if book_ok[i][TOKEN_BTC] {
            if exch_a.is_none() { exch_a = Some(i); } else { exch_b = Some(i); break; }
        }
    }

    if let (Some(ea), Some(eb)) = (exch_a, exch_b) {
        let orig_bid = prices[ea][TOKEN_BTC].0;
        if orig_bid > 0 {
            let inflated_bid = orig_bid + (orig_bid / 67);
            let inflated_ask = inflated_bid + (orig_bid / 500);
            arena.update_price(eb, TOKEN_BTC, inflated_bid, inflated_ask);
            arena.build_cross_exchange_targets().await;
            let sigs = arena.evaluate_tick(eb, TOKEN_BTC, 0, 0);
            for sig in sigs {
                if matches!(sig, ArbitrageSignal::CrossExchange { .. }) {
                    all_signals.push(sig);
                }
            }
        }
    }

    // Inject triangular
    if let Some(&ei) = exchange_pairs.keys().next() {
        let idx_btc = arena.get_index(ei as usize, TOKEN_BTC);
        let idx_eth = arena.get_index(ei as usize, TOKEN_ETH);
        let idx_sol = arena.get_index(ei as usize, TOKEN_SOL);
        let ask_btc = arena.ask_prices[idx_btc].load(Ordering::Acquire);
        let ask_eth = arena.ask_prices[idx_eth].load(Ordering::Acquire);
        let ask_sol = arena.ask_prices[idx_sol].load(Ordering::Acquire);

        if ask_btc > 0 && ask_eth > 0 && ask_sol > 0 {
            arena.bid_prices[idx_btc].store(ask_btc + (ask_btc / 50), Ordering::Release);
            arena.bid_prices[idx_eth].store(ask_eth + (ask_eth / 50), Ordering::Release);
            arena.bid_prices[idx_sol].store(ask_sol + (ask_sol / 50), Ordering::Release);
            let sigs = arena.evaluate_tick(ei as usize, TOKEN_BTC, 0, 0);
            for sig in sigs {
                if matches!(sig, ArbitrageSignal::Triangular { .. }) {
                    all_signals.push(sig);
                }
            }
        }
    }
}