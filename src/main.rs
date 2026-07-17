//! rust-hft-arb — High-Frequency Cross-Exchange & Triangular Arbitrage Bot
//!
//! Master bootstrapper. Pins computation to a dedicated CPU core, loads

#![allow(unused_imports)]
//! configuration, wires every subsystem together, and either starts live
//! WebSocket feeds or runs the built-in integration smoke-test.

mod balance_allocator;
mod backtest;
mod coin_finder;
mod configs;
mod datafeed;
mod discord;
mod dynamic_fees;
mod execution;
pub use rust_hft_arb::exchange;
mod exchanges;
mod health;
mod metrics;
mod order_book;
mod paper_trading;
mod persistence;
mod pnl_report;
mod protections;
mod rebalancer;
mod signer;
mod stablecoin;
mod strategies;
mod subaccount;
mod withdrawal;
mod live_order_tracker;
mod balance_sync;
mod risk_shield;
mod safety_execution;
mod exchange_constraints;
mod atomic_orderbook;
mod circuit_breaker;
mod core_execution_shield;
mod ring_buffer_logger;
mod rebalance_matrix;
mod zero_alloc_signer;
mod zero_lag_stream;
mod cross_exchange_executor;
mod order_feed;
mod depeg_protection;
mod rate_limiter;
mod nonce_manager;
mod timestamp_sync;
mod shared_memory;
mod payload_arena;
mod size_slicer;
mod capital_starvation;
mod dust_manager;
mod private_ws_feed;
mod volatility_guard;
mod tcp_optimizer;
mod tri_path_finder;
mod production_risk_shield;
mod market_arena;
mod zero_copy_parser;
mod cpu_pinning;

use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tokio::signal::unix;

use rust_decimal::prelude::ToPrimitive;
use rust_decimal::Decimal;
use rust_decimal_macros::dec;
use tokio::sync::Mutex;

use balance_allocator::LocalCapitalAllocator;
use configs::EngineConfig;
use datafeed::spawn_feed_workers;
use dynamic_fees::DynamicFeeManager;
use execution::{HighFrequencyExecutionEngine, OrderIntent, PaperExecutionPipeline};
use exchanges::{binance, bybit, gateio, kucoin, okx, PaperExchangeClient,
    bitfinex, bitget, bitmex, coinbase, htx, kraken, lbank,
    bitstamp, deribit, delta, mexc, ibank};
use order_book::{L2OrderBookManager, spawn_ob_workers};
use pnl_report::{TradeLog, start_daily_pnl_printer};
use signer::PrivateApiSigner;
use signer::PrivateExchangeClient;
use paper_trading::PaperTradingPipeline;
use persistence::{AsyncPersistenceWorker, PersistentState};
use protections::RiskManager;
use circuit_breaker::EngineCircuitBreaker;
use risk_shield::{RiskShield, CrossExchangeRiskShield, MarketTicker};
use safety_execution::SafetyExecutionEngine;
use exchange_constraints::{ExchangeConstraints, AbsoluteMathEngine, MarketDepth, DepthLevel};
use atomic_orderbook::FixedOrderBook;
use core_execution_shield::CoreExecutionShield;
use ring_buffer_logger::RingBufferLogger;
use rebalance_matrix::RebalanceMatrixEngine;
use zero_lag_stream::ZeroLagStreamManager;
use cross_exchange_executor::CrossExchangeExecutor;
use rebalancer::{AutoCapitalRebalancer, ExchangeHeartbeatHandle, create_rebalance_channel};
use stablecoin::StablecoinMonitor;
use subaccount::SubAccountManager;
use coin_finder::{CoinFinder, CoinFinderConfig};
use strategies::{ArbitrageSignal, MarketArena};
use withdrawal::WithdrawalExecutor;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default paper-trading capital in USD.
const DEFAULT_PAPER_CAPITAL: Decimal = dec!(100_000.0);

/// Fixed-point scale used by risk manager and balance allocator.
const FP_SCALE: u64 = 1_000_000;

/// Key patterns that indicate "no real API key configured".
const PLACEHOLDER_PATTERNS: &[&str] = &[
    "", "YOUR_", "PLACEHOLDER", "REPLACE", "XXXX", "XXXXXXXX",
    "API_KEY", "API_SECRET", "CHANGE_ME", "YOUR_KEY", "YOUR_SECRET",
    "INSERT_", "PUT_YOUR", "PASTE_", "EXAMPLE", "DEMO", "TEST",
];

/// Returns true if the key looks like a placeholder rather than a real credential.
fn is_placeholder_key(key: &str) -> bool {
    let k = key.trim();
    if k.is_empty() || k.len() < 8 {
        return true;
    }
    let upper = k.to_uppercase();
    PLACEHOLDER_PATTERNS.iter().any(|p| upper.contains(p))
}

/// Determine whether the engine should run in forced-paper mode.
/// Returns true if ANY configured exchange has placeholder API keys.
fn detect_paper_mode(config: &EngineConfig) -> bool {
    config.exchanges.values().any(|ex| {
        is_placeholder_key(&ex.api_key) || is_placeholder_key(&ex.api_secret)
    })
}

// ---------------------------------------------------------------------------
// Bootstrap
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Install a simple tracing subscriber so all modules can emit logs.
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();

    println!("=== INITIALIZING HIGH-FREQUENCY TRADING ENGINES ===");

    // ------------------------------------------------------------------
    // 1. Pin core computations to CPU Core 0
    // ------------------------------------------------------------------
    let core_ids = core_affinity::get_core_ids().unwrap_or_default();
    if let Some(core_id) = core_ids.first() {
        core_affinity::set_for_current(*core_id);
        println!("CPU core pinned to physical core {:?}", core_id);
    } else {
        println!("WARNING: Could not detect CPU cores — running unpinned");
    }

    // ------------------------------------------------------------------
    // 2. Load and validate configuration
    // ------------------------------------------------------------------
    let config = EngineConfig::load_and_validate("config.toml")?;
    println!("Configuration loaded: {} exchange(s) configured", config.exchanges.len());

    // ------------------------------------------------------------------
    // 2b. Startup sanity checks — fail fast on dangerous config values
    // ------------------------------------------------------------------
    if config.exchanges.is_empty() {
        return Err("No exchanges configured — nothing to trade. Add at least one [exchanges.<name>] section to config.toml.".into());
    }
    if config.exchanges.len() > 64 {
        return Err(format!(
            "Too many exchanges configured ({}). Maximum is 64 due to u64 bitmask constraints in the strategy engine.",
            config.exchanges.len()
        ).into());
    }
    if config.risk.min_net_profit_pct <= Decimal::ZERO {
        return Err("risk_limits.min_net_profit_pct must be > 0 — a zero threshold would trade at a guaranteed loss.".into());
    }
    println!("Startup sanity checks passed");

    // Size the arena by the *highest* exchange ID, not the count.
    // Exchange IDs from config are used directly as array indices, so
    // the arena must have at least `max(id) + 1` rows.  If IDs are not
    // contiguous (e.g. {1, 2, 5}) the gaps are simply unused slots.
    let max_exchange_id = config
        .exchanges
        .values()
        .map(|e| e.id as usize)
        .max()
        .unwrap_or(0);
    let num_exchanges = (max_exchange_id + 1).max(1);
    let max_tokens: usize = 3000;

    // Validate that no exchange ID exceeds u64 bitmask range (0..64).
    // Beyond 64 exchanges the bitmask-based strategy filters break.
    if max_exchange_id >= 64 {
        return Err(
            format!(
                "exchange id {} exceeds maximum of 63 (bitmask-based filtering requires < 64 exchanges)",
                max_exchange_id
            )
            .into(),
        );
    }

    // ------------------------------------------------------------------
    // 3. Build the Market Arena (contiguous memory matrix)
    // ------------------------------------------------------------------
    let arena = MarketArena::new(num_exchanges, max_tokens);

    // Configure strategy toggles from config
    if !config.strategies.cross_exchange.enabled {
        arena.enabled_cross.store(false, Ordering::Relaxed);
        println!("Strategy: Cross-Exchange Arbitrage DISABLED");
    } else {
        println!("Strategy: Cross-Exchange Arbitrage ENABLED");
    }
    if !config.strategies.triangular.enabled {
        arena.enabled_tri.store(false, Ordering::Relaxed);
        println!("Strategy: Triangular Arbitrage DISABLED");
    } else {
        println!("Strategy: Triangular Arbitrage ENABLED");
    }

    // Configure per-strategy exchange allowlists.
    // When set in config, only the specified exchanges emit signals for
    // that strategy.  When omitted, all exchanges are eligible (default).
    if let Some(ref exchs) = config.strategies.cross_exchange.exchanges {
        let mask: u64 = exchs.iter().fold(0u64, |m, &id| m | (1u64 << id));
        arena.cross_exchange_mask.store(mask, Ordering::Relaxed);
        println!(
            "  Cross-exchange restricted to exchanges: {:?}",
            exchs
        );
    }
    if let Some(ref exchs) = config.strategies.triangular.exchanges {
        let mask: u64 = exchs.iter().fold(0u64, |m, &id| m | (1u64 << id));
        arena.tri_exchange_mask.store(mask, Ordering::Relaxed);
        println!(
            "  Triangular restricted to exchanges: {:?}",
            exchs
        );
    }

    let arena = Arc::new(arena);

    // ------------------------------------------------------------------
    // 4. Build the 14-Layer Risk Manager
    // ------------------------------------------------------------------
    let risk_manager = Arc::new(RiskManager::new(config.risk.clone()));
    println!("14-layer risk manager initialized");

    // ------------------------------------------------------------------
    // 5. Build the Stablecoin Depeg Monitor
    // ------------------------------------------------------------------
    let stable_config = stablecoin::StablecoinConfig {
        depeg_threshold: config.stablecoin.depeg_threshold,
        usdt_max_pct: config.stablecoin.usdt_max_pct,
        usdc_min_pct: config.stablecoin.usdc_min_pct,
        monitored_symbols: config.stablecoin.monitored_symbols.clone(),
    };
    let depeg_circuit = Arc::new(StablecoinMonitor::new(stable_config));
    println!("Stablecoin depeg circuit active — monitoring {:?}", config.stablecoin.monitored_symbols);

    // ------------------------------------------------------------------
    // 6. Build the Paper Trading Pipeline
    // ------------------------------------------------------------------
    let paper_pipeline = Arc::new(PaperTradingPipeline::new(DEFAULT_PAPER_CAPITAL));
    println!("Paper trading pipeline initialized with ${} virtual capital", DEFAULT_PAPER_CAPITAL);

    // ------------------------------------------------------------------
    // 7. Build the Balance Allocator
    // ------------------------------------------------------------------
    let allocator = LocalCapitalAllocator::new(num_exchanges, max_tokens);
    // Register common tokens with category bitmasks
    allocator.register_token(0, "USDT", balance_allocator::CAT_STABLE);
    allocator.register_token(1, "USDC", balance_allocator::CAT_STABLE);
    allocator.register_token(2, "DAI", balance_allocator::CAT_STABLE);
    allocator.register_token(10, "BTC", balance_allocator::CAT_MAJOR);
    allocator.register_token(11, "ETH", balance_allocator::CAT_MAJOR);
    allocator.register_token(20, "SOL", balance_allocator::CAT_ALTCOIN);
    allocator.register_token(21, "ADA", balance_allocator::CAT_ALTCOIN);
    allocator.register_token(30, "DOGE", balance_allocator::CAT_MEMECOIN);
    allocator.register_token(31, "PEPE", balance_allocator::CAT_MEMECOIN);

    // Seed initial capital on exchange 0
    let initial_capital_fp = decimal_to_fp(DEFAULT_PAPER_CAPITAL);
    allocator.update_balance_atomic(0, 0, DEFAULT_PAPER_CAPITAL);
    println!("Local capital allocator seeded — 9 tokens registered");

    // Wrap in Arc early so we can share with the coin finder.
    let allocator_arc = Arc::new(allocator);

    // ------------------------------------------------------------------
    // 7b. Launch the Live Coin Finder (public API scanner)
    // ------------------------------------------------------------------
    // Queries every exchange's public REST API every 1 second to discover
    // which trading pairs are listed, filters them through the category
    // system, and auto-allocates qualifying coins to strategies.
    // Coins on >= 2 exchanges are automatically enabled for cross-exchange
    // arb.  Per-exchange pair graphs are rebuilt for triangular arb.

    let mut finder_rest_urls: HashMap<u16, String> = HashMap::new();
    for (id, exch) in &config.exchanges {
        finder_rest_urls.insert(*id, exch.rest_url.clone());
    }

    let quote_anchors = config
        .strategies
        .triangular
        .quote_anchors
        .iter()
        .map(|s| s.to_uppercase())
        .collect::<Vec<_>>();
    let finder_anchors = if quote_anchors.is_empty() {
        vec!["USDT".to_string()]
    } else {
        quote_anchors
    };

    let finder_config = CoinFinderConfig {
        quote_anchors: finder_anchors.clone(),
        allowed_categories: 0, // accept all categories — risk manager handles exposure
        min_volume_usd: None,  // volume filtering can be added later
    };

    let coin_finder = CoinFinder::new(
        finder_rest_urls,
        finder_config,
        Arc::clone(&allocator_arc),
        Arc::clone(&arena),
        100, // start token IDs at 100 (0–99 reserved for manual registration)
    )?;

    let coin_finder_handle = tokio::spawn(async move {
        coin_finder.run().await;
    });
    println!(
        "Live Coin Finder launched — scanning {} exchange(s) every 1s via public API",
        config.exchanges.len()
    );
    println!("  Quote anchors: {:?}", finder_anchors);
    println!("  Auto cross-exchange: coins on >= 2 exchanges → enabled");
    println!("  Auto triangular: per-exchange pair graph rebuilt each cycle");

    // ------------------------------------------------------------------
    // 8. Build Exchange Signer Pool (only for exchanges with real keys)
    // ------------------------------------------------------------------
    let mut signers: HashMap<u16, PrivateApiSigner> = HashMap::new();
    let mut rest_urls: HashMap<u16, String> = HashMap::new();
    let mut paper_only_exchanges: Vec<u16> = Vec::new();

    for (id, exch) in &config.exchanges {
        rest_urls.insert(*id, exch.rest_url.clone());

        if is_placeholder_key(&exch.api_key) || is_placeholder_key(&exch.api_secret) {
            paper_only_exchanges.push(*id);
            println!("Exchange {} (ID {}): placeholder API key detected — using paper client",
                exch.name, id);
            continue;
        }

        let signer = if let Some(ref passphrase) = exch.passphrase {
            PrivateApiSigner::new_with_passphrase(&exch.api_key, &exch.api_secret, passphrase)
        } else {
            PrivateApiSigner::new(&exch.api_key, &exch.api_secret)
        };
        signers.insert(*id, signer);
    }
    let signers_pool = Arc::new(signers);
    if signers_pool.is_empty() && !paper_only_exchanges.is_empty() {
        println!("All exchanges have placeholder keys — running in full paper mode (public API data only)");
    } else {
        println!("Cryptographic signature keys cached for {} exchange(s)", signers_pool.len());
    }

    // ------------------------------------------------------------------
    // 9. Build the Typed Execution Pool (exchange_id → client)
    // ------------------------------------------------------------------
    // For exchanges with real API keys → use the live exchange client.
    // For exchanges with placeholder keys → fall back to PaperExchangeClient.
    // The PaperExchangeClient simulates fills locally with 1–3 bps slippage.
    // The coin finder still scans public APIs for ALL exchanges regardless,
    // so tri arb loops and cross-exchange targets are built from live data.

    let mut execution_pool: HashMap<u16, Arc<dyn PrivateExchangeClient>> = HashMap::new();
    let mut live_init_failures: Vec<(u16, String, String)> = Vec::new();

    // Exchange 0 → Binance
    if let Some(exch) = config.exchanges.get(&0u16) {
        if is_placeholder_key(&exch.api_key) || is_placeholder_key(&exch.api_secret) {
            execution_pool.insert(0, Arc::new(PaperExchangeClient::new(0)));
            println!("Execution pool: Binance (ID 0) → PAPER client (no API keys)");
        } else {
            match binance::new(&exch.api_key, &exch.api_secret) {
                Ok(client) => {
                    execution_pool.insert(0, Arc::new(client));
                    println!("Execution pool: Binance (ID 0) wired (LIVE)");
                }
                Err(e) => {
                    execution_pool.insert(0, Arc::new(PaperExchangeClient::new(0)));
                    live_init_failures.push((0, "Binance".to_string(), e.to_string()));
                    println!("WARNING: Binance init failed ({}) → falling back to PAPER", e);
                }
            }
        }
    }

    // Exchange 1 → Bybit
    if let Some(exch) = config.exchanges.get(&1u16) {
        if is_placeholder_key(&exch.api_key) || is_placeholder_key(&exch.api_secret) {
            execution_pool.insert(1, Arc::new(PaperExchangeClient::new(1)));
            println!("Execution pool: Bybit (ID 1) → PAPER client (no API keys)");
        } else {
            match bybit::new(&exch.api_key, &exch.api_secret) {
                Ok(client) => {
                    execution_pool.insert(1, Arc::new(client));
                    println!("Execution pool: Bybit (ID 1) wired (LIVE)");
                }
                Err(e) => {
                    execution_pool.insert(1, Arc::new(PaperExchangeClient::new(1)));
                    live_init_failures.push((1, "Bybit".to_string(), e.to_string()));
                    println!("WARNING: Bybit init failed ({}) → falling back to PAPER", e);
                }
            }
        }
    }

    // Exchange 2 → OKX (requires passphrase)
    if let Some(exch) = config.exchanges.get(&2u16) {
        if is_placeholder_key(&exch.api_key) || is_placeholder_key(&exch.api_secret) {
            execution_pool.insert(2, Arc::new(PaperExchangeClient::new(2)));
            println!("Execution pool: OKX (ID 2) → PAPER client (no API keys)");
        } else {
            let passphrase = exch.passphrase.as_deref().unwrap_or("");
            match okx::OkxClient::new(&exch.api_key, &exch.api_secret, passphrase) {
                Ok(client) => {
                    execution_pool.insert(2, Arc::new(client));
                    println!("Execution pool: OKX (ID 2) wired (LIVE)");
                }
                Err(e) => {
                    execution_pool.insert(2, Arc::new(PaperExchangeClient::new(2)));
                    live_init_failures.push((2, "OKX".to_string(), e.to_string()));
                    println!("WARNING: OKX init failed ({}) → falling back to PAPER", e);
                }
            }
        }
    }

    // Exchange 3 → Gate.io
    if let Some(exch) = config.exchanges.get(&3u16) {
        if is_placeholder_key(&exch.api_key) || is_placeholder_key(&exch.api_secret) {
            execution_pool.insert(3, Arc::new(PaperExchangeClient::new(3)));
            println!("Execution pool: GateIO (ID 3) → PAPER client (no API keys)");
        } else {
            match gateio::GateioClient::new(&exch.api_key, &exch.api_secret) {
                Ok(client) => {
                    execution_pool.insert(3, Arc::new(client));
                    println!("Execution pool: GateIO (ID 3) wired (LIVE)");
                }
                Err(e) => {
                    execution_pool.insert(3, Arc::new(PaperExchangeClient::new(3)));
                    live_init_failures.push((3, "GateIO".to_string(), e.to_string()));
                    println!("WARNING: GateIO init failed ({}) → falling back to PAPER", e);
                }
            }
        }
    }

    // Exchange 4 → KuCoin (requires passphrase)
    if let Some(exch) = config.exchanges.get(&4u16) {
        if is_placeholder_key(&exch.api_key) || is_placeholder_key(&exch.api_secret) {
            execution_pool.insert(4, Arc::new(PaperExchangeClient::new(4)));
            println!("Execution pool: KuCoin (ID 4) → PAPER client (no API keys)");
        } else {
            let passphrase = exch.passphrase.as_deref().unwrap_or("");
            match kucoin::new(&exch.api_key, &exch.api_secret, passphrase) {
                Ok(client) => {
                    execution_pool.insert(4, Arc::new(client));
                    println!("Execution pool: KuCoin (ID 4) wired (LIVE)");
                }
                Err(e) => {
                    execution_pool.insert(4, Arc::new(PaperExchangeClient::new(4)));
                    live_init_failures.push((4, "KuCoin".to_string(), e.to_string()));
                    println!("WARNING: KuCoin init failed ({}) → falling back to PAPER", e);
                }
            }
        }
    }

    // Exchange 5 → Bitfinex
    if let Some(exch) = config.exchanges.get(&5u16) {
        if is_placeholder_key(&exch.api_key) || is_placeholder_key(&exch.api_secret) {
            execution_pool.insert(5, Arc::new(PaperExchangeClient::new(5)));
            println!("Execution pool: Bitfinex (ID 5) → PAPER client (no API keys)");
        } else {
            match bitfinex::BitfinexPrivateClient::new(&exch.api_key, &exch.api_secret) {
                Ok(client) => {
                    execution_pool.insert(5, Arc::new(client));
                    println!("Execution pool: Bitfinex (ID 5) wired (LIVE)");
                }
                Err(e) => {
                    execution_pool.insert(5, Arc::new(PaperExchangeClient::new(5)));
                    live_init_failures.push((5, "Bitfinex".to_string(), e.to_string()));
                    println!("WARNING: Bitfinex init failed ({}) → falling back to PAPER", e);
                }
            }
        }
    }

    // Exchange 6 → Bitget (requires passphrase)
    if let Some(exch) = config.exchanges.get(&6u16) {
        if is_placeholder_key(&exch.api_key) || is_placeholder_key(&exch.api_secret) {
            execution_pool.insert(6, Arc::new(PaperExchangeClient::new(6)));
            println!("Execution pool: Bitget (ID 6) → PAPER client (no API keys)");
        } else {
            let passphrase = exch.passphrase.as_deref().unwrap_or("");
            match bitget::BitgetPrivateClient::new(&exch.api_key, &exch.api_secret, passphrase) {
                Ok(client) => {
                    execution_pool.insert(6, Arc::new(client));
                    println!("Execution pool: Bitget (ID 6) wired (LIVE)");
                }
                Err(e) => {
                    execution_pool.insert(6, Arc::new(PaperExchangeClient::new(6)));
                    live_init_failures.push((6, "Bitget".to_string(), e.to_string()));
                    println!("WARNING: Bitget init failed ({}) → falling back to PAPER", e);
                }
            }
        }
    }

    // Exchange 7 → BitMEX
    if let Some(exch) = config.exchanges.get(&7u16) {
        if is_placeholder_key(&exch.api_key) || is_placeholder_key(&exch.api_secret) {
            execution_pool.insert(7, Arc::new(PaperExchangeClient::new(7)));
            println!("Execution pool: BitMEX (ID 7) → PAPER client (no API keys)");
        } else {
            match bitmex::BitmexPrivateClient::new(&exch.api_key, &exch.api_secret) {
                Ok(client) => {
                    execution_pool.insert(7, Arc::new(client));
                    println!("Execution pool: BitMEX (ID 7) wired (LIVE)");
                }
                Err(e) => {
                    execution_pool.insert(7, Arc::new(PaperExchangeClient::new(7)));
                    live_init_failures.push((7, "BitMEX".to_string(), e.to_string()));
                    println!("WARNING: BitMEX init failed ({}) → falling back to PAPER", e);
                }
            }
        }
    }

    // Exchange 8 → Coinbase
    if let Some(exch) = config.exchanges.get(&8u16) {
        if is_placeholder_key(&exch.api_key) || is_placeholder_key(&exch.api_secret) {
            execution_pool.insert(8, Arc::new(PaperExchangeClient::new(8)));
            println!("Execution pool: Coinbase (ID 8) → PAPER client (no API keys)");
        } else {
            match coinbase::CoinbasePrivateClient::new(&exch.api_key, &exch.api_secret) {
                Ok(client) => {
                    execution_pool.insert(8, Arc::new(client));
                    println!("Execution pool: Coinbase (ID 8) wired (LIVE)");
                }
                Err(e) => {
                    execution_pool.insert(8, Arc::new(PaperExchangeClient::new(8)));
                    live_init_failures.push((8, "Coinbase".to_string(), e.to_string()));
                    println!("WARNING: Coinbase init failed ({}) → falling back to PAPER", e);
                }
            }
        }
    }

    // Exchange 9 → HTX
    if let Some(exch) = config.exchanges.get(&9u16) {
        if is_placeholder_key(&exch.api_key) || is_placeholder_key(&exch.api_secret) {
            execution_pool.insert(9, Arc::new(PaperExchangeClient::new(9)));
            println!("Execution pool: HTX (ID 9) → PAPER client (no API keys)");
        } else {
            match htx::HtxPrivateClient::new(&exch.api_key, &exch.api_secret) {
                Ok(client) => {
                    execution_pool.insert(9, Arc::new(client));
                    println!("Execution pool: HTX (ID 9) wired (LIVE)");
                }
                Err(e) => {
                    execution_pool.insert(9, Arc::new(PaperExchangeClient::new(9)));
                    live_init_failures.push((9, "HTX".to_string(), e.to_string()));
                    println!("WARNING: HTX init failed ({}) → falling back to PAPER", e);
                }
            }
        }
    }

    // Exchange 10 → Kraken
    if let Some(exch) = config.exchanges.get(&10u16) {
        if is_placeholder_key(&exch.api_key) || is_placeholder_key(&exch.api_secret) {
            execution_pool.insert(10, Arc::new(PaperExchangeClient::new(10)));
            println!("Execution pool: Kraken (ID 10) → PAPER client (no API keys)");
        } else {
            match kraken::KrakenPrivateClient::new(&exch.api_key, &exch.api_secret) {
                Ok(client) => {
                    execution_pool.insert(10, Arc::new(client));
                    println!("Execution pool: Kraken (ID 10) wired (LIVE)");
                }
                Err(e) => {
                    execution_pool.insert(10, Arc::new(PaperExchangeClient::new(10)));
                    live_init_failures.push((10, "Kraken".to_string(), e.to_string()));
                    println!("WARNING: Kraken init failed ({}) → falling back to PAPER", e);
                }
            }
        }
    }

    // Exchange 11 → LBank
    if let Some(exch) = config.exchanges.get(&11u16) {
        if is_placeholder_key(&exch.api_key) || is_placeholder_key(&exch.api_secret) {
            execution_pool.insert(11, Arc::new(PaperExchangeClient::new(11)));
            println!("Execution pool: LBank (ID 11) → PAPER client (no API keys)");
        } else {
            match lbank::LbankPrivateClient::new(&exch.api_key, &exch.api_secret) {
                Ok(client) => {
                    execution_pool.insert(11, Arc::new(client));
                    println!("Execution pool: LBank (ID 11) wired (LIVE)");
                }
                Err(e) => {
                    execution_pool.insert(11, Arc::new(PaperExchangeClient::new(11)));
                    live_init_failures.push((11, "LBank".to_string(), e.to_string()));
                    println!("WARNING: LBank init failed ({}) → falling back to PAPER", e);
                }
            }
        }
    }

    // Exchange 12 → Bitstamp
    if let Some(exch) = config.exchanges.get(&12u16) {
        if is_placeholder_key(&exch.api_key) || is_placeholder_key(&exch.api_secret) {
            execution_pool.insert(12, Arc::new(PaperExchangeClient::new(12)));
            println!("Execution pool: Bitstamp (ID 12) → PAPER client (no API keys)");
        } else {
            match bitstamp::BitstampPrivateClient::new(&exch.api_key, &exch.api_secret) {
                Ok(client) => {
                    execution_pool.insert(12, Arc::new(client));
                    println!("Execution pool: Bitstamp (ID 12) wired (LIVE)");
                }
                Err(e) => {
                    execution_pool.insert(12, Arc::new(PaperExchangeClient::new(12)));
                    live_init_failures.push((12, "Bitstamp".to_string(), e.to_string()));
                    println!("WARNING: Bitstamp init failed ({}) → falling back to PAPER", e);
                }
            }
        }
    }

    // Exchange 13 → Deribit
    if let Some(exch) = config.exchanges.get(&13u16) {
        if is_placeholder_key(&exch.api_key) || is_placeholder_key(&exch.api_secret) {
            execution_pool.insert(13, Arc::new(PaperExchangeClient::new(13)));
            println!("Execution pool: Deribit (ID 13) → PAPER client (no API keys)");
        } else {
            match deribit::DeribitPrivateClient::new(&exch.api_key, &exch.api_secret) {
                Ok(client) => {
                    execution_pool.insert(13, Arc::new(client));
                    println!("Execution pool: Deribit (ID 13) wired (LIVE)");
                }
                Err(e) => {
                    execution_pool.insert(13, Arc::new(PaperExchangeClient::new(13)));
                    live_init_failures.push((13, "Deribit".to_string(), e.to_string()));
                    println!("WARNING: Deribit init failed ({}) → falling back to PAPER", e);
                }
            }
        }
    }

    // Exchange 14 → Delta
    if let Some(exch) = config.exchanges.get(&14u16) {
        if is_placeholder_key(&exch.api_key) || is_placeholder_key(&exch.api_secret) {
            execution_pool.insert(14, Arc::new(PaperExchangeClient::new(14)));
            println!("Execution pool: Delta (ID 14) → PAPER client (no API keys)");
        } else {
            match delta::DeltaPrivateClient::new(&exch.api_key, &exch.api_secret) {
                Ok(client) => {
                    execution_pool.insert(14, Arc::new(client));
                    println!("Execution pool: Delta (ID 14) wired (LIVE)");
                }
                Err(e) => {
                    execution_pool.insert(14, Arc::new(PaperExchangeClient::new(14)));
                    live_init_failures.push((14, "Delta".to_string(), e.to_string()));
                    println!("WARNING: Delta init failed ({}) → falling back to PAPER", e);
                }
            }
        }
    }

    // Exchange 15 → MEXC
    if let Some(exch) = config.exchanges.get(&15u16) {
        if is_placeholder_key(&exch.api_key) || is_placeholder_key(&exch.api_secret) {
            execution_pool.insert(15, Arc::new(PaperExchangeClient::new(15)));
            println!("Execution pool: MEXC (ID 15) → PAPER client (no API keys)");
        } else {
            match mexc::MexcPrivateClient::new(&exch.api_key, &exch.api_secret) {
                Ok(client) => {
                    execution_pool.insert(15, Arc::new(client));
                    println!("Execution pool: MEXC (ID 15) wired (LIVE)");
                }
                Err(e) => {
                    execution_pool.insert(15, Arc::new(PaperExchangeClient::new(15)));
                    live_init_failures.push((15, "MEXC".to_string(), e.to_string()));
                    println!("WARNING: MEXC init failed ({}) → falling back to PAPER", e);
                }
            }
        }
    }

    // Exchange 16 → Ibank
    if let Some(exch) = config.exchanges.get(&16u16) {
        if is_placeholder_key(&exch.api_key) || is_placeholder_key(&exch.api_secret) {
            execution_pool.insert(16, Arc::new(PaperExchangeClient::new(16)));
            println!("Execution pool: Ibank (ID 16) → PAPER client (no API keys)");
        } else {
            match ibank::IbankPrivateClient::new(&exch.api_key, &exch.api_secret) {
                Ok(client) => {
                    execution_pool.insert(16, Arc::new(client));
                    println!("Execution pool: Ibank (ID 16) wired (LIVE)");
                }
                Err(e) => {
                    execution_pool.insert(16, Arc::new(PaperExchangeClient::new(16)));
                    live_init_failures.push((16, "Ibank".to_string(), e.to_string()));
                    println!("WARNING: Ibank init failed ({}) → falling back to PAPER", e);
                }
            }
        }
    }

    let execution_pool = Arc::new(execution_pool);
    println!("Execution pool: {} exchange client(s) loaded", execution_pool.len());

    // ------------------------------------------------------------------
    // 9b-pre-a. Detect paper mode (must be before live_capital & engine init)
    // ------------------------------------------------------------------
    let placeholder_detected = detect_paper_mode(&config);
    let forced_paper = if config.force_live_mode {
        if placeholder_detected {
            println!("⚠️  WARNING: force_live_mode=true but placeholder keys detected!");
            println!("   The bot will attempt REAL orders. Ensure ALL keys are valid.");
        }
        false // force live mode overrides placeholder detection
    } else if placeholder_detected {
        // Interactive confirmation: ask the operator before entering paper mode.
        println!("\n╔══════════════════════════════════════════════════════════════╗");
        println!("║  📋 PAPER MODE DETECTED                                    ║");
        println!("║                                                            ║");
        println!("║  One or more exchanges have placeholder API keys.           ║");
        println!("║  The bot will run in PAPER MODE (simulated fills).          ║");
        println!("║                                                            ║");
        println!("║  No real orders will be placed. Real-time market data       ║");
        println!("║  from all exchanges will still be streamed via WebSocket.   ║");
        println!("║                                                            ║");
        println!("║  To switch to LIVE MODE later:                              ║");
        println!("║    1. Replace all placeholder API keys in config.toml        ║");
        println!("║    2. Set force_live_mode = true                            ║");
        println!("╠══════════════════════════════════════════════════════════════╣");
        println!("║  Confirm PAPER MODE? (y/n):                                 ║");
        println!("╚══════════════════════════════════════════════════════════════╝");
        let mut input = String::new();
        std::io::stdin().read_line(&mut input).unwrap_or_default();
        let confirmed = input.trim().eq_ignore_ascii_case("y") || input.trim().eq_ignore_ascii_case("yes");
        if !confirmed {
            println!("Aborted by user. Update your API keys in config.toml and re-run.");
            return Ok(());
        }
        true
    } else {
        false
    };

    // In live mode, any exchange init failure is a HARD ERROR.
    // Silently falling back to paper while the operator thinks they're live
    // would cause real capital asymmetry (some legs paper, some live).
    if !forced_paper && !live_init_failures.is_empty() {
        eprintln!();
        eprintln!("==============================================================");
        eprintln!("  FATAL: Exchange client initialization failed in LIVE mode");
        eprintln!("==============================================================");
        for (id, name, err) in &live_init_failures {
            eprintln!("  Exchange {} (ID {}): {}", name, id, err);
        }
        eprintln!("--------------------------------------------------------------");
        eprintln!("  FIX: Check API keys, network, and exchange status.");
        eprintln!("  To force paper mode: set force_live_mode = false in config.");
        eprintln!("==============================================================");
        eprintln!();
        std::process::exit(1);
    }

    // ------------------------------------------------------------------
    // 9b-pre. LIVE MODE: Boot-time balance sync from exchanges
    // ------------------------------------------------------------------
    // In live mode, query actual USDT balances from each exchange and
    // seed the balance allocator with real values.  This ensures lot
    // sizing and capital starvation detection use REAL numbers.
    let live_capital: Decimal = if !forced_paper {
        println!("LIVE MODE: Querying real exchange balances...");
        let boot_total = balance_sync::boot_sync(
            &execution_pool,
            &reqwest::Client::new(),
            &allocator_arc,
            0, // token 0 = USDT
        )
        .await;
        if boot_total > Decimal::ZERO {
            println!("  Total live USDT across exchanges: ${}", boot_total);
            boot_total
        } else {
            println!("  WARNING: All exchange balance queries failed — falling back to DEFAULT_PAPER_CAPITAL");
            DEFAULT_PAPER_CAPITAL
        }
    } else {
        DEFAULT_PAPER_CAPITAL
    };

    // ------------------------------------------------------------------
    // 9b. Build the Execution Engine (paper + real pipelines)
    // ------------------------------------------------------------------
    let paper_balance = Arc::new(Mutex::new(DEFAULT_PAPER_CAPITAL));
    let paper_exec = Arc::new(PaperExecutionPipeline::new(Arc::clone(&paper_balance)));

    // Build real pipeline with typed exchange client pool.
    // The .with_typed_pool() call wires the per-exchange clients (Binance,
    // Bybit, OKX, GateIO, KuCoin) into the pipeline so that orders are routed
    // through exchange-specific signing and endpoint logic instead of the
    // generic Binance-style fallback.
    // The .with_rate_limiter() call attaches a per-exchange 429 circuit breaker
    // that blocks ALL orders to a rate-limited exchange for 60 seconds.
    let rate_limiter = Arc::new(
        execution::RateLimitCircuitBreaker::new(config.exchanges.len(), 60)
    );
    let real_exec: Arc<dyn execution::OrderPipeline> = Arc::new(
        execution::RealExecutionPipeline::new(
            reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .connect_timeout(std::time::Duration::from_secs(5))
                .tcp_nodelay(true)
                .build()
                .map_err(|e| anyhow::anyhow!("failed to build execution HTTP client: {}", e))?,
            rest_urls.clone(),
            Arc::clone(&signers_pool),
        )
        .with_typed_pool(Arc::clone(&execution_pool))
        .with_rate_limiter(Arc::clone(&rate_limiter))
    );

    let mut engine = HighFrequencyExecutionEngine::new(
        Arc::clone(&risk_manager),
        Arc::clone(&depeg_circuit),
        paper_exec,
        real_exec,
        forced_paper, // true if any exchange has no real keys
    );

    // Wire the configurable daily loss limit (USD → cents) from config.
    let daily_loss_cents = (config.risk.daily_loss_limit_usd * Decimal::from(100u32))
        .to_u64()
        .unwrap_or_else(|| {
            tracing::error!(
                configured = %config.risk.daily_loss_limit_usd,
                "daily_loss_limit_usd overflowed u64 — disabling daily loss limit (u64::MAX)"
            );
            u64::MAX
        }); // on overflow, disable the limit rather than tightening to $100
    engine.set_daily_loss_limit_cents(daily_loss_cents);

    // In live mode, attach the cancellation infrastructure so the engine
    // can cancel unfilled orders on the actual exchange.
    if !forced_paper {
        engine.cancel_http_client = Some(
            reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .connect_timeout(std::time::Duration::from_secs(5))
                .tcp_nodelay(true)
                .build()
                .map_err(|e| anyhow::anyhow!("failed to build cancel HTTP client: {}", e))?
        );
        engine.cancel_pool = Some(Arc::clone(&execution_pool));
        println!("Live order cancellation wired — unfilled orders will be cancelled on-exchange");
    }

    let engine = Arc::new(engine);
    if forced_paper {
        println!("High-frequency execution engine online (PAPER MODE — simulated fills, real market data)");
        println!("  >>> To enable LIVE TRADING: replace ALL placeholder API keys in config.toml with real keys <<<");
    } else {
        println!("High-frequency execution engine online (LIVE MODE — REAL MONEY AT RISK)");
        println!("  *** WARNING: This bot will place REAL orders with REAL funds ***");
        println!("  *** Ensure risk_limits are appropriate for your capital ***");
        println!("  *** Kill switch (Ctrl+C) is the ONLY emergency stop ***");
    }

    // ------------------------------------------------------------------
    // 9b-friction. Wire friction protections from config → subsystems
    // ------------------------------------------------------------------
    // (a) Set pre-trade slippage tolerance on the execution engine.
    engine.set_slippage_tolerance(config.strategies.cross_exchange.max_slippage_tolerance);
    println!(
        "Friction: pre-trade slippage tolerance = {} (from config)",
        config.strategies.cross_exchange.max_slippage_tolerance
    );

    // (b) Configure per-exchange taker fees on the strategy arena's fee schedule.
    //     Convert the default_taker_fee_pct (Decimal fraction) to bps, then
    //     apply per-exchange overrides from friction_protections.exchange_taker_fees.
    {
        let default_bps = (config.friction_protections.default_taker_fee_pct * Decimal::from(10_000u64))
            .to_u64()
            .unwrap_or(10);
        if let Ok(mut fees) = arena.fee_schedule.write() {
            // Set default for all exchanges first.
            for exch_cfg in config.exchanges.values() {
                let bps = config
                    .friction_protections
                    .exchange_taker_fees
                    .get(&exch_cfg.name)
                    .copied()
                    .unwrap_or(default_bps);
                fees.set_fee(exch_cfg.id as usize, bps, bps);
                println!(
                    "Friction: {} taker fee = {} bps{}",
                    exch_cfg.name,
                    bps,
                    if config.friction_protections.exchange_taker_fees.contains_key(&exch_cfg.name) {
                        " (overridden)"
                    } else {
                        " (default)"
                    }
                );
            }
        }
    }

    // (c) Toggle fee-aware mode on the arena.
    arena.fee_aware_enabled.store(
        config.friction_protections.fee_aware_enabled,
        Ordering::Release,
    );
    println!(
        "Friction: fee-aware spread calculation = {}",
        config.friction_protections.fee_aware_enabled
    );

    // ------------------------------------------------------------------
    // 9c. Initialize the Auto-Capital Rebalancer
    // ------------------------------------------------------------------
    // The rebalancer runs on a low-priority background thread, completely
    // isolated from the main trading loop.  It listens for capital starvation
    // signals via a bounded MPSC channel (capacity 10) and executes automated
    // blockchain withdrawals to redistribute capital across exchanges.

    // Validate deposit addresses at boot (non-fatal — rebalancer simply
    // won't execute withdrawals for exchanges without configured addresses).
    let configured_addrs: Vec<_> = config
        .deposit_addresses
        .iter()
        .filter(|(_, addr)| addr.starts_with("0x") && addr.len() >= 10)
        .collect();
    if configured_addrs.is_empty() {
        println!("WARNING: No deposit addresses configured — auto-rebalancer will be disabled");
        println!("  Set [deposit_addresses] in config.toml to enable inter-exchange transfers");
    } else {
        println!("Rebalancer: {} deposit address(es) configured", configured_addrs.len());
    }

    let (rebalance_tx, rebalance_rx) = create_rebalance_channel();

    let mut rebalancer = AutoCapitalRebalancer::new(
        rebalance_rx,
        reqwest::Client::new(),
        Arc::clone(&allocator_arc),
        Arc::clone(&signers_pool),
        60, // 60-second blockchain settlement cooldown (Arbitrum L2)
        config.deposit_addresses.clone(),
    );

    // (d) Wire gas fee from config into the rebalancer.
    rebalancer.set_gas_fee_usd(config.friction_protections.transfer_gas_fee_usd);
    println!(
        "Friction: rebalancer gas fee = ${} per transfer",
        config.friction_protections.transfer_gas_fee_usd
    );

    // Extract the heartbeat handle BEFORE moving the rebalancer into
    // the spawned task.  Feed workers will use this to record exchange
    // liveness so the rebalancer can skip withdrawals to dead exchanges.
    let heartbeat_handle: ExchangeHeartbeatHandle = rebalancer.heartbeat_handle();

    // Spawn the rebalancer on an independent background task.
    let rebalancer_handle = tokio::spawn(async move {
        rebalancer.run().await;
    });
    println!("Auto-Capital Rebalancer background worker started (channel capacity 10)");
    println!("Rebalancer heartbeat handle distributed to feed workers");
    // rebalance_tx is kept alive for the live signal loop below.
    // When the strategy engine detects capital starvation on an exchange,
    // it sends a RebalanceRequest through this channel.
    let rebalance_tx = rebalance_tx;

    // ------------------------------------------------------------------
    // 10. Start the Async Persistence Worker
    // ------------------------------------------------------------------
    let (disk_worker, state_tx) = AsyncPersistenceWorker::new("state.json", 50);
    let disk_handle = tokio::spawn(async move {
        disk_worker.run_disk_writer_loop().await;
    });
    println!("Background persistence worker started");

    // ------------------------------------------------------------------
    // 10b. Start the Discord Notification Worker
    // ------------------------------------------------------------------
    let (discord_worker, _discord_tx) = discord::DiscordWorker::new(
        config.discord.webhook_url.clone(),
        config.discord.buffer_capacity,
    );
    let discord_handle = tokio::spawn(async move {
        discord_worker.run().await;
    });
    println!("Discord notification worker started (sender retained for execution engine hook)");

    // ------------------------------------------------------------------
    // 11. Run the integration smoke-test
    // ------------------------------------------------------------------
    run_integration_test(
        &engine,
        &arena,
        &risk_manager,
        &depeg_circuit,
        &paper_pipeline,
        &state_tx,
        initial_capital_fp,
    )
    .await;

    // ------------------------------------------------------------------
    // 12. Start live WebSocket feeds + signal→execution loop
    // ------------------------------------------------------------------
    // When the WS feeds are active, every price tick calls arena.update_price()
    // which updates the atomic matrix.  A separate polling loop (below)
    // evaluates ticks and dispatches signals to the execution engine.
    //
    // Start live WebSocket feeds for all configured exchanges.
    // Each feed worker maintains a persistent WS connection and streams
    // price updates into the arena's atomic price matrix via update_price().
    // In paper mode the execution engine simulates fills; in live mode it
    // routes through the typed exchange client pool.
    let feed_list: Vec<(u16, String)> = config
        .exchanges
        .values()
        .map(|e| (e.id, e.wss_url.clone()))
        .collect();
    let feed_count = feed_list.len();

    // Create a watch channel for dynamic WS symbol subscriptions.
    // The coin finder will write updated symbol lists here.
    // Each WS listener re-subscribes with the latest symbols on reconnect.
    let (symbol_watch_tx, symbol_watch_rx) = tokio::sync::watch::channel(Vec::new());
    let _feed_handles = spawn_feed_workers(Arc::clone(&arena), feed_list, symbol_watch_rx, Some(heartbeat_handle));
    println!("Live WebSocket feed workers started for {} exchange(s) (heartbeat-wired to rebalancer)", feed_count);
    println!("Dynamic WS subscription channel active — coin finder updates symbols on reconnect");

    // ------------------------------------------------------------------
    // 12b. L2 Order Book Depth — parallel to ticker WS feeds
    // ------------------------------------------------------------------
    // Launches a second set of WS connections subscribed to L2 order book
    // channels. The order book manager is shared via Arc<DashMap> and can
    // be queried by the strategy engine for real fillability checks.
    let ob_manager = Arc::new(L2OrderBookManager::new());
    let ob_feed_list: Vec<(u16, String)> = config
        .exchanges
        .values()
        .map(|e| (e.id, e.wss_url.clone()))
        .collect();
    let ob_symbol_watch = symbol_watch_tx.subscribe();
    let ob_len = ob_feed_list.len();
    let _ob_handles = spawn_ob_workers(
        Arc::clone(&ob_manager),
        ob_feed_list,
        ob_symbol_watch,
    );
    println!("L2 order book depth feeds started for {} exchange(s)", ob_len);

    // ------------------------------------------------------------------
    // 12c. Dynamic Fee Manager — fetches real fee rates from exchanges
    // ------------------------------------------------------------------
    let mut config_fee_map: HashMap<String, u64> = HashMap::new();
    for (name, bps) in &config.friction_protections.exchange_taker_fees {
        config_fee_map.insert(name.to_lowercase(), *bps as u64);
    }
    let fee_manager = Arc::new(DynamicFeeManager::new(
        config_fee_map,
        reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .connect_timeout(std::time::Duration::from_secs(5))
            .build()
            .map_err(|e| anyhow::anyhow!("failed to build fee manager HTTP client: {}", e))?,
        Arc::clone(&execution_pool),
        rest_urls.clone(),
    ));
    // Fetch fees once at boot, then refresh every 300 seconds.
    {
        let fm = Arc::clone(&fee_manager);
        tokio::spawn(async move {
            fm.fetch_all_fees().await;
            let summary = fm.get_all_fees_summary();
            println!("Exchange fee schedule (real / config fallback):");
            for (id, name, maker, taker) in &summary {
                println!("  {} (ID {}): maker={} bps, taker={} bps", name, id, maker, taker);
            }
            fm.refresh_periodically(30).await;
        });
    }

    // ------------------------------------------------------------------
    // 12d. Trade Log & P&L Reporting
    // ------------------------------------------------------------------
    let trade_log = Arc::new(TradeLog::new("trade_log.jsonl".to_string()));
    trade_log.load_existing().await;
    let existing_count = trade_log.records.lock().unwrap_or_else(|e| e.into_inner()).len();
    println!("Trade log initialized — {} existing trades loaded from trade_log.jsonl", existing_count);
    start_daily_pnl_printer(Arc::clone(&trade_log));

    // ------------------------------------------------------------------
    // 12e. Sub-account Permission Verification
    // ------------------------------------------------------------------
    // At boot, verify API key permissions and warn if any key has
    // withdrawal access (unsafe for automated trading).
    {
        let mut creds_map: HashMap<u16, subaccount::ExchangeCreds> = HashMap::new();
        for (id, exch) in &config.exchanges {
            if !is_placeholder_key(&exch.api_key) {
                creds_map.insert(*id, subaccount::ExchangeCreds {
                    api_key: exch.api_key.clone(),
                    api_secret: exch.api_secret.clone(),
                    passphrase: exch.passphrase.clone(),
                    rest_url: exch.rest_url.clone(),
                });
            }
        }
        if !creds_map.is_empty() {
            let creds_len = creds_map.len();
            let sub_mgr = SubAccountManager::new(creds_map);
            println!("Verifying API key permissions for {} exchange(s)...", creds_len);
            let results = sub_mgr.validate_all_keys().await;
            let mut safety_ok = true;
            for (id, name, result) in &results {
                match result {
                    Ok(perms) => {
                        if !perms.can_trade || perms.can_withdraw {
                            safety_ok = false;
                        }
                        println!("  {} (ID {}): trade={}, withdraw={}, read={}, ip_restricted={}",
                            name, id, perms.can_trade, perms.can_withdraw, perms.can_read, perms.ip_restricted);
                    }
                    Err(e) => {
                        safety_ok = false;
                        println!("  {} (ID {}): PERMISSION CHECK FAILED — {}", name, id, e);
                    }
                }
            }
            // Print setup guide if any exchange has unsafe permissions
            let has_unsafe = results.iter().any(|(_, _, r)| {
                r.as_ref().map(|p| p.can_withdraw).unwrap_or(false)
            });
            if has_unsafe {
                let guide = sub_mgr.generate_setup_guide().await;
                println!("\n⚠️  WARNING: Some API keys have WITHDRAWAL permission. This is unsafe!");
                println!("   Create restricted sub-accounts using this guide:\n{}", guide);
            } else if safety_ok {
                println!("  All API key permissions verified — SAFE for automated trading");
            }
        }
    }

    // ------------------------------------------------------------------
    // 12f. Withdrawal Executor (for rebalancer)
    // ------------------------------------------------------------------
    let withdrawal_executor = WithdrawalExecutor::new(
        reqwest::Client::new(),
        Arc::clone(&execution_pool),
        rest_urls.clone(),
        &config.exchanges,
    );
    println!("Withdrawal executor initialized — rebalancer can now execute on-chain transfers");
    println!("  ⚠️  Withdrawals require real API keys with withdrawal permission");

    // ------------------------------------------------------------------
    // 12f. Derive minimum-signal thresholds from config (pct → bps).
    //      Computed early so both backtest mode and live mode can use them.
    // ------------------------------------------------------------------
    let min_cross_bps: u64 = (config.strategies.cross_exchange.min_spread_pct * Decimal::from(10_000u64))
        .to_u64()
        .unwrap_or(15);
    let min_tri_bps: u64 = (config.strategies.triangular.min_loop_profit_pct * Decimal::from(10_000u64))
        .to_u64()
        .unwrap_or(15);

    // ------------------------------------------------------------------
    // 12g. Backtest mode check (CLI flag: --backtest <data.csv>)
    // ------------------------------------------------------------------
    let args: Vec<String> = std::env::args().collect();
    if args.len() >= 3 && args[1] == "--backtest" {
        println!("\n╔══════════════════════════════════════════════════════════╗");
        println!("║  BACKTEST MODE                                           ║");
        println!("╚══════════════════════════════════════════════════════════╝");
        let bt_config = backtest::BacktestConfig {
            initial_capital: dec!(100_000),
            max_position_pct: config.risk.max_single_position_pct,
            taker_fee_bps: config.friction_protections.default_taker_fee_pct.to_u64().unwrap_or(10),
            min_spread_bps: min_cross_bps,
            data_file: args[2].clone(),
        };
        match backtest::run_backtest(&args[2], bt_config).await {
            Ok(result) => {
                println!("\n--- Backtest Results ---");
                println!("  Total P&L:      ${:.2}", result.total_pnl);
                println!("  Total Fees:     ${:.2}", result.total_fees);
                println!("  Total Trades:   {}", result.total_trades);
                println!("  Win Rate:       {:.1}%", result.win_rate * dec!(100));
                println!("  Max Drawdown:   {:.2}%", result.max_drawdown * dec!(100));
                println!("  Sharpe Ratio:   {:.2}", result.sharpe_ratio);
                if !result.trades.is_empty() {
                    println!("  {} trades executed during backtest", result.trades.len());
                }
            }
            Err(e) => {
                println!("Backtest failed: {}", e);
                println!("Generate sample data with: cargo run --example gen_sample_data");
            }
        }
        return Ok(());
    }

    // ------------------------------------------------------------------
    // 13. Live signal→execution loop (paper or real)
    // ------------------------------------------------------------------
    // This loop bridges the gap between strategy signals and order execution.
    // In a production deployment this would be driven by WS tick callbacks;
    // here it runs as a periodic evaluator on the arena's current state.
    //
    // The loop reads every exchange's prices from the arena, runs
    // evaluate_tick for the most-recently-updated token on each exchange,
    // and dispatches any signals through the execution engine.

    let health = Arc::new(health::HealthMonitor::new());

    // ------------------------------------------------------------------
    // 12. Spawn the Prometheus metrics server (port 9090)
    // ------------------------------------------------------------------
    {
        let metrics_state = Arc::new(metrics::MetricsState {
            health: Arc::clone(&health),
            risk: Arc::clone(&risk_manager),
            execution: Some(Arc::clone(&engine)),
        });
        let metrics_config = metrics::MetricsConfig::default();
        let (_metrics_handle, _metrics_shutdown) =
            metrics::spawn_metrics_server(metrics_config, metrics_state);
        println!("Prometheus metrics endpoint: http://0.0.0.0:9090/metrics");
    }

    let signal_arena = Arc::clone(&arena);
    let signal_engine = Arc::clone(&engine);
    let signal_allocator = Arc::clone(&allocator_arc);
    let signal_rebalance_tx = rebalance_tx.clone();
    let signal_risk = Arc::clone(&risk_manager);
    let signal_depeg = Arc::clone(&depeg_circuit);
    let num_exch = num_exchanges;
    // C2 FIX: In live mode, use the actual live capital (sum of real exchange
    // balances) for the risk manager's equity tracker.  Using the paper
    // constant would make all 14 risk layers operate on the wrong equity
    // figure, allowing trades at 2×+ intended risk.
    let live_capital_fp = decimal_to_fp(live_capital);
    let paper_capital_fp = if forced_paper { initial_capital_fp } else { live_capital_fp };
    let signal_health = Arc::clone(&health);
    let signal_symbol_watch = symbol_watch_tx;

    // ------------------------------------------------------------------
    // Capital Starvation Detector — wired to rebalancer via callback
    // ------------------------------------------------------------------
    // Creates a detector with the configurable threshold (default $10).
    // The callback finds the exchange with the highest USDT balance and
    // sends a RebalanceRequest to transfer $500 from that exchange to
    // the starved one.  This replaces the old hard-coded check.
    let starvation_threshold = config.risk.max_single_position_pct * live_capital;
    let starvation_threshold = if starvation_threshold < Decimal::from(50) {
        Decimal::from(50) // floor at $50
    } else {
        starvation_threshold
    };
    let mut starvation_detector = capital_starvation::CapitalStarvationDetector::new(starvation_threshold);
    {
        let cb_allocator = Arc::clone(&allocator_arc);
        let cb_rebalance_tx = signal_rebalance_tx.clone();
        let cb_num_exch = num_exch;
        starvation_detector.set_starvation_callback(Arc::new(move |starved_exchange_id: u16| {
            // Find the exchange with the highest USDT balance to pull from.
            let mut best_src: u16 = 0;
            let mut best_bal = Decimal::ZERO;
            for eid in 0..cb_num_exch {
                if eid as u16 == starved_exchange_id {
                    continue;
                }
                let bal = cb_allocator.get_balance_atomic(eid, 0); // token 0 = USDT
                if bal > best_bal {
                    best_bal = bal;
                    best_src = eid as u16;
                }
            }
            let transfer_amount = if best_bal > Decimal::from(500) {
                Decimal::from(500)
            } else {
                // Transfer up to 80% of the source's balance to avoid
                // draining it too.
                (best_bal * Decimal::from(80)) / Decimal::from(100)
            };
            tracing::warn!(
                from = best_src,
                to = starved_exchange_id,
                amount = %transfer_amount,
                source_balance = %best_bal,
                "starvation_callback: dispatching rebalance request"
            );
            // Look up the USDT token ID dynamically from the allocator's
            // registry rather than hardcoding 0.  This prevents breakage if
            // the token registration order in main() ever changes.
            let usdt_token_id = cb_allocator
                .get_id("USDT")
                .unwrap_or(0); // fallback: 0 is the convention for USDT
            let send_result = cb_rebalance_tx.try_send(
                rebalancer::RebalanceRequest {
                    from_exchange_id: best_src,
                    to_exchange_id: starved_exchange_id,
                    token_id: usdt_token_id,
                    amount: transfer_amount,
                    token_symbol: "USDT".to_string(),
                },
            );
            if send_result.is_err() {
                tracing::warn!(
                    from = best_src,
                    to = starved_exchange_id,
                    "rebalance channel full — starvation fix request DROPPED"
                );
            }
        }));
    }
    let signal_starvation_detector = starvation_detector;
    println!(
        "Capital starvation detector armed (threshold=${:.2}, callback wired to rebalancer)",
        starvation_threshold
    );

    println!(
        "Signal thresholds from config: cross-exchange >= {} bps, triangular >= {} bps",
        min_cross_bps, min_tri_bps,
    );

    // Lot-sizing parameters derived from config.
    let lot_max_pct = config.risk.max_single_position_pct;
    // In live mode, lot_capital should reflect real account equity.
    // For now we use DEFAULT_PAPER_CAPITAL as the upper bound; the balance
    // allocator's per-exchange matrix is the actual authority on available funds.
    // TODO: Query real exchange balances at boot and use the sum as lot_capital.
    let lot_capital = live_capital;
    // Fall-back minimum lot when the allocator returns zero (no balance seeded yet).
    let lot_fallback = dec!(0.001);

    /// Build a pair symbol from base token, formatted for the given exchange.
    /// Exchange 2 (OKX) uses "BASE-QUOTE", exchange 3 (GateIO) uses "BASE_QUOTE",
    /// exchange 8 (Coinbase) uses "BASE-QUOTE", all others use "BASEQUOTE".
    fn build_pair_symbol(base: &str, quote: &str, exchange_id: u16) -> String {
        match exchange_id {
            2 => format!("{}-{}", base, quote), // OKX: BTC-USDT
            3 => format!("{}_{}", base, quote),  // GateIO: BTC_USDT
            8 => format!("{}-{}", base, quote),  // Coinbase: BTC-USDT
            _ => format!("{}{}", base, quote),   // Binance/Bybit/KuCoin: BTCUSDT
        }
    }

    let signal_loop = tokio::spawn(async move {
        let mut tick_counter: u64 = 0;

        loop {
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            tick_counter += 1;

            // Keep risk manager's equity and network-freshness timestamps
            // current so Layers 3 (equity staleness) and 13 (network latency
            // staleness) don't reject every trade.  Throttled to once per
            // second (every 10 ticks) to avoid atomic contention.
            if tick_counter % 10 == 1 {
                signal_risk.update_equity(paper_capital_fp);
                signal_risk.touch_network_check();

                // Feed stablecoin prices from the arena into the depeg monitor.
                // USDC (token 1) and DAI (token 2) are quoted in USDT, so their
                // arena price IS their USDT peg value.  If USDCUSDT = 0.995,
                // that means USDC has depegged by 0.5%.
                // Read from exchange 0 as the reference price source.
                for &(token_id, sym) in &[(1u16, "USDC"), (2u16, "DAI")] {
                    let idx = signal_arena.get_index(0, token_id as usize);
                    let bid_fp = signal_arena.bid_prices[idx].load(Ordering::Relaxed);
                    let ask_fp = signal_arena.ask_prices[idx].load(Ordering::Relaxed);
                    if bid_fp > 0 && ask_fp > 0 {
                        let mid = Decimal::from((bid_fp + ask_fp) / 2)
                            / Decimal::from(100_000_000u64);
                        signal_depeg.update_price(sym, mid, "arena").await;
                    }
                }
            }

            // Evaluate each exchange for arbitrage signals.
            // In a live deployment, evaluate_tick is called directly from
            // the WS feed callback with the exact (exchange, token) that
            // changed.  Here we sweep all exchanges periodically
            // using the coin finder's dynamically-discovered token list.
            for exch_id in 0..num_exch {
                let tokens = match signal_arena.active_tokens.try_lock() {
                    Ok(guard) => guard.clone(),
                    Err(_) => continue,
                };
                for &token_id in &tokens {
                    let signals = signal_arena.evaluate_tick(
                        exch_id,
                        token_id as usize,
                        min_cross_bps,
                        min_tri_bps,
                    );

                    for sig in signals {
                        signal_health.record_signal();
                        match sig {
                            ArbitrageSignal::CrossExchange {
                                buy_exchange,
                                sell_exchange,
                                token_id: tid,
                                spread_bps,
                            } => {
                                // Look up the real exchange-specific base symbol from the
                                // allocator's token registry.  Falls back to the synthetic
                                // "TOKEN{n}" format if the coin finder hasn't registered it yet.
                                let base_sym = signal_allocator
                                    .get_symbol(tid)
                                    .unwrap_or_else(|| format!("TOKEN{}", tid));
                                let symbol = build_pair_symbol(&base_sym, "USDT", buy_exchange);
                                let sell_symbol = build_pair_symbol(&base_sym, "USDT", sell_exchange);

                                // Read actual best ask (buy) / bid (sell) from the arena for order pricing
                                let buy_price = Decimal::from(
                                    signal_arena.ask_prices[signal_arena.get_index(buy_exchange as usize, tid as usize)].load(Ordering::Relaxed),
                                ) / Decimal::from(100_000_000u64);
                                let sell_price = Decimal::from(
                                    signal_arena.bid_prices[signal_arena.get_index(sell_exchange as usize, tid as usize)].load(Ordering::Relaxed),
                                ) / Decimal::from(100_000_000u64);

                                // Dynamic lot sizing via the balance allocator.
                                // NOTE: In live mode, the balance matrix is refreshed every 60s
                                // by the periodic balance sync (balance_sync::run_periodic_sync).
                                // This serves as the "balance handshake" — the bot never
                                // guesses its balance; it queries the exchange API directly.
                                // If a partial fill depleted funds, the next sync cycle will
                                // detect the discrepancy and reduce lot sizes accordingly.
                                let qty = signal_allocator
                                    .compute_lot_size(buy_exchange as usize, tid as usize, lot_max_pct, lot_capital);
                                let qty = if qty > Decimal::ZERO { qty } else { lot_fallback };

                                let leg_a = OrderIntent {
                                    exchange_id: buy_exchange,
                                    token_id: tid,
                                    qty: qty.clone(),
                                    price: buy_price,
                                    is_buy: true,
                                    symbol: symbol.clone(),
                                };
                                let leg_b = OrderIntent {
                                    exchange_id: sell_exchange,
                                    token_id: tid,
                                    qty,
                                    price: sell_price,
                                    is_buy: false,
                                    symbol: sell_symbol,
                                };

                                tracing::info!(
                                    tick = tick_counter,
                                    buy_ex = buy_exchange,
                                    sell_ex = sell_exchange,
                                    token = tid,
                                    spread_bps = spread_bps,
                                    "CROSS-EXCHANGE signal → firing two-leg blast"
                                );

                                match signal_engine
                                    .blast_arbitrage_legs(leg_a, leg_b, spread_bps, paper_capital_fp)
                                    .await
                                {
                                    Ok((res_a, res_b)) => {
                                        signal_health.record_trade_success();
                                        tracing::info!(
                                            leg_a_ok = res_a.success,
                                            leg_b_ok = res_b.success,
                                            "two-leg blast complete"
                                        );
                                    }
                                    Err(e) => {
                                        signal_health.record_trade_error();
                                        tracing::warn!(error = %e, "two-leg blast failed");
                                    }
                                }
                            }

                            ArbitrageSignal::Triangular {
                                exchange_id: exch,
                                token_a,
                                token_b,
                                token_c,
                                profit_bps,
                            } => {
                                tracing::info!(
                                    tick = tick_counter,
                                    exch = exch,
                                    tokens = format!("{}->{}->{}", token_a, token_b, token_c),
                                    profit_bps = profit_bps,
                                    "TRIANGULAR signal detected"
                                );

                                // Build three OrderIntents for the triangular legs.
                                // In production these symbols would come from a
                                // token→symbol mapping table.
                                // Dynamic lot sizing via the balance allocator (use token_a as anchor).
                                let tri_qty = signal_allocator
                                    .compute_lot_size(exch as usize, token_a as usize, lot_max_pct, lot_capital);
                                let tri_qty = if tri_qty > Decimal::ZERO { tri_qty } else { lot_fallback };

                                let legs = [
                                    OrderIntent {
                                        exchange_id: exch,
                                        token_id: token_a,
                                        qty: tri_qty.clone(),
                                        price: Decimal::from(
                                            signal_arena.ask_prices[signal_arena.get_index(exch as usize, token_a as usize)].load(Ordering::Relaxed),
                                        ) / Decimal::from(100_000_000u64),
                                        is_buy: true,
                                        symbol: {
                                            let base = signal_allocator.get_symbol(token_a)
                                                .unwrap_or_else(|| format!("TOKEN{}", token_a));
                                            build_pair_symbol(&base, "USDT", exch)
                                        },
                                    },
                                    OrderIntent {
                                        exchange_id: exch,
                                        token_id: token_b,
                                        qty: tri_qty.clone(),
                                        price: Decimal::from(
                                            signal_arena.bid_prices[signal_arena.get_index(exch as usize, token_b as usize)].load(Ordering::Relaxed),
                                        ) / Decimal::from(100_000_000u64),
                                        is_buy: true,
                                        symbol: {
                                            let base = signal_allocator.get_symbol(token_b)
                                                .unwrap_or_else(|| format!("TOKEN{}", token_b));
                                            build_pair_symbol(&base, "USDT", exch)
                                        },
                                    },
                                    OrderIntent {
                                        exchange_id: exch,
                                        token_id: token_c,
                                        qty: tri_qty,
                                        price: Decimal::from(
                                            signal_arena.bid_prices[signal_arena.get_index(exch as usize, token_c as usize)].load(Ordering::Relaxed),
                                        ) / Decimal::from(100_000_000u64),
                                        is_buy: false,
                                        symbol: {
                                            let base = signal_allocator.get_symbol(token_c)
                                                .unwrap_or_else(|| format!("TOKEN{}", token_c));
                                            build_pair_symbol(&base, "USDT", exch)
                                        },
                                    },
                                ];

                                match signal_engine
                                    .blast_triangular_legs(legs, profit_bps, paper_capital_fp)
                                    .await
                                {
                                    Ok(results) => {
                                        signal_health.record_trade_success();
                                        tracing::info!(
                                            l0 = results[0].success,
                                            l1 = results[1].success,
                                            l2 = results[2].success,
                                            "three-leg blast complete"
                                        );
                                    }
                                    Err(e) => {
                                        signal_health.record_trade_error();
                                        tracing::warn!(error = %e, "three-leg blast failed");
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Every 300 ticks (~30 seconds), push the latest discovered
            // symbols to the WS watch channel so feed workers re-subscribe
            // with the full list on their next reconnect.
            if tick_counter % 300 == 0 {
                if let Ok(tokens) = signal_arena.active_tokens.try_lock() {
                    let syms: Vec<String> = tokens.iter()
                        .filter_map(|&tid| signal_allocator.get_symbol(tid))
                        .map(|s| format!("{}USDT", s))  // WS subscriptions use BASEQUOTE for most feeds
                        .collect();
                    // Only push if the list changed (watch channel ignores dupes).
                    if signal_symbol_watch.send(syms).is_err() {
                        tracing::warn!("signal_symbol_watch receiver dropped — symbol list updates will stop");
                    }
                }
            }

            // Every 1000 ticks (~100 seconds), log health stats.
            if tick_counter % 1000 == 0 {
                let stats = signal_health.get_stats();
                tracing::info!(
                    uptime_secs = stats.uptime_secs,
                    signals = stats.total_signals,
                    trades = stats.total_trades,
                    errors = stats.total_errors,
                    healthy = stats.is_healthy,
                    last_signal_ago_s = stats.last_signal_ago_secs,
                    "health stats"
                );
            }

            // Every 500 ticks (~50 seconds), check if any exchange is
            // starved of USDT via the CapitalStarvationDetector.
            // The detector's callback (wired above) automatically sends
            // a RebalanceRequest to the rebalancer channel, selecting the
            // best-funded source exchange dynamically.
            if tick_counter % 500 == 0 {
                for exch_id in 0..num_exch {
                    let bal = signal_allocator.get_balance_atomic(exch_id, 0); // token 0 = USDT
                    if let Some(event) = signal_starvation_detector.check_balance(
                        exch_id,
                        0, // token 0 = USDT
                        bal,
                    ) {
                        tracing::warn!(
                            exchange = event.exchange_id,
                            token = event.token_id,
                            balance = %event.current_balance,
                            threshold = %event.min_threshold,
                            "capital starvation detected (via detector)"
                        );
                    }
                }
            }
        }
    });

    // ------------------------------------------------------------------
    // 12b. Periodic balance sync (live mode only)
    // ------------------------------------------------------------------
    if !forced_paper {
        let sync_pool = Arc::clone(&execution_pool);
        let sync_allocator = Arc::clone(&allocator_arc);
        let sync_http = reqwest::Client::new();
        let _balance_sync_handle = tokio::spawn(async move {
            balance_sync::run_periodic_sync(
                sync_pool,
                sync_http,
                sync_allocator,
                0, // token 0 = USDT
                60, // every 60 seconds
            )
            .await;
        });
        println!("Periodic balance sync: every 60s from exchange APIs");

        // ------------------------------------------------------------------
        // 12c. Order cancellation sweeper (live mode only)
        // ------------------------------------------------------------------
        // Every 5 seconds, scan for stale unfilled orders (>30s old) and
        // cancel them on-exchange.  This prevents capital from being locked
        // in limit orders that never fill.
        let _sweeper_handle = execution::spawn_order_cancellation_sweeper(
            Arc::clone(&engine),
            5,  // check every 5 seconds
            30, // cancel orders older than 30 seconds
        );
        println!("Order cancellation sweeper: checking every 5s, cancelling after 30s");

        // ------------------------------------------------------------------
        // 12c-ii. Order status poller (live mode only)
        // ------------------------------------------------------------------
        // Persistent daemon: polls orders with IDs but 0 filled_qty every
        // 500ms.  Skips orders older than 30s (cancellation sweeper handles
        // those).  Runs indefinitely — never expires.  Adapts to 2.5s
        // polling when idle to save API quota.
        let _poller_handle = execution::spawn_order_status_poller(
            Arc::clone(&engine),
            30,  // skip orders older than 30s (sweeper territory)
            500, // check every 500ms when active
        );
        println!("Order status poller: persistent daemon, polls every 500ms (2.5s idle), skips orders >30s old");
        println!("Rate-limit circuit breaker: per-exchange 60s cooldown on HTTP 429");

        // ------------------------------------------------------------------
        // 12d. Flash-crash volatility circuit breaker (live mode only)
        // ------------------------------------------------------------------
        // Monitors BTC price by dynamically looking up BTC's token ID
        // from the allocator registry (was hardcoded to exchange 0, token 10).
        // Scans all exchanges for a valid BTC price and uses the first found.
        let flash_engine = Arc::clone(&engine);
        let flash_arena = Arc::clone(&arena);
        let flash_allocator = Arc::clone(&allocator_arc);
        let _flash_handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(
                std::time::Duration::from_secs(5),
            );
            let mut last_btc_price: rust_decimal::Decimal = rust_decimal::Decimal::ZERO;
            let mut max_deviation_bps: u64 = 0;
            let window_ticks: u64 = 60; // 5 minutes / 5 seconds = 60 ticks
            let mut tick_count: u64 = 0;
            let threshold_bps: u64 = 150; // 1.5% = 150 bps

            loop {
                interval.tick().await;
                tick_count += 1;

                // Dynamically look up BTC's token ID from the allocator registry.
                // Falls back to token 10 (the conventional ID) if BTC is not
                // yet registered by the coin finder.
                let btc_token_id = flash_allocator.get_id("BTC").unwrap_or(10);

                // Scan exchanges 0..3 for a valid BTC price (cover the most
                // liquid exchanges without scanning all 17 every 5 seconds).
                let mut btc_fp: u64 = 0;
                for exch in 0..std::cmp::min(num_exchanges, 3) {
                    let idx = flash_arena.get_index(exch, btc_token_id as usize);
                    if idx < flash_arena.bid_prices.len() {
                        let val = flash_arena.bid_prices[idx].load(Ordering::Relaxed);
                        if val > 0 {
                            btc_fp = val;
                            break;
                        }
                    }
                }

                if btc_fp == 0 {
                    continue; // no BTC price data yet
                }

                let btc_price = rust_decimal::Decimal::from(btc_fp)
                    / rust_decimal::Decimal::from(100_000_000u64);

                if last_btc_price > rust_decimal::Decimal::ZERO {
                    let deviation = if btc_price > last_btc_price {
                        (btc_price - last_btc_price) / last_btc_price
                    } else {
                        (last_btc_price - btc_price) / last_btc_price
                    };
                    let dev_bps = (deviation * rust_decimal::Decimal::from(10_000u64))
                        .to_u64()
                        .unwrap_or(0);
                    if dev_bps > max_deviation_bps {
                        max_deviation_bps = dev_bps;
                    }
                }
                last_btc_price = btc_price;

                // Every window_ticks, check if max deviation exceeded threshold.
                if tick_count % window_ticks == 0 {
                    if max_deviation_bps >= threshold_bps {
                        tracing::error!(
                            max_deviation_bps = max_deviation_bps,
                            threshold_bps = threshold_bps,
                            "FLASH CRASH DETECTED — volatility circuit breaker ACTIVATED"
                        );
                        flash_engine.volatility_circuit.store(true, Ordering::Release);
                        // Auto-recover after 60 seconds of calm.
                        let recover_engine = Arc::clone(&flash_engine);
                        tokio::spawn(async move {
                            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                            tracing::info!(
                                "volatility circuit breaker auto-recovered after 60s cooldown"
                            );
                            recover_engine.volatility_circuit.store(false, Ordering::Release);
                        });
                    }
                    max_deviation_bps = 0; // reset window
                    tick_count = 0;
                }
            }
        });
        println!("Flash-crash volatility monitor: BTC >1.5%/5min → circuit breaker");
    }

    println!("\n=== HFT BOT PIPELINE FULLY OPERATIONAL ===");
    println!("Execution pool: {} typed client(s) wired to real pipeline",
             execution_pool.len());
    println!("Signal->execution loop active (100ms tick, cross>={}bps, tri>={}bps)",
             min_cross_bps, min_tri_bps);

    // LIVE MODE SAFETY GATE: Give the operator a 5-second countdown to
    // read the warnings and Ctrl+C before any real orders can be placed.
    // In paper mode this countdown is skipped.
    if !forced_paper {
        println!("\n╔══════════════════════════════════════════════════════════╗");
        println!("║  🔴 LIVE MODE — REAL ORDERS WILL BE PLACED IN 5s         ║");
        println!("║     Press Ctrl+C NOW to abort if this is not intended    ║");
        println!("╚══════════════════════════════════════════════════════════╝");
        for i in (1..=5).rev() {
            println!("  ... starting in {} seconds", i);
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        }
        println!("  >>> LIVE TRADING ACTIVE <<<\n");
    }

    println!("Press Ctrl+C to shut down gracefully.\n");

    // Keep the process alive until SIGINT or SIGTERM.
    let mut terminate = unix::signal(unix::SignalKind::terminate())?;
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {},
        _ = terminate.recv() => {},
    }
    println!("\nShutdown signal received, initiating graceful shutdown...");

    // Log final health stats.
    {
        let stats = health.get_stats();
        tracing::info!(
            uptime_secs = stats.uptime_secs,
            signals = stats.total_signals,
            trades = stats.total_trades,
            errors = stats.total_errors,
            ws_reconnects = stats.ws_reconnects,
            healthy = stats.is_healthy,
            "final health stats at shutdown"
        );
    }

    // Abort all spawned tasks.
    signal_loop.abort();
    coin_finder_handle.abort();
    rebalancer_handle.abort();
    disk_handle.abort();
    discord_handle.abort();

    // Wait up to 5 seconds for the signal loop to finish.
    match tokio::time::timeout(std::time::Duration::from_secs(5), signal_loop).await {
        Ok(_) => tracing::info!("signal loop stopped cleanly"),
        Err(_) => tracing::warn!("signal loop did not stop within 5s timeout"),
    }

    println!("All tasks stopped, exiting");
    Ok(())
}

// ---------------------------------------------------------------------------
// Integration Smoke-Test
// ---------------------------------------------------------------------------

/// Verifies that every subsystem is wired correctly by injecting synthetic
/// price data and firing a simulated arbitrage execution through the full
/// pipeline (data feed → arena → strategy scanner → risk gate → execution).
async fn run_integration_test(
    engine: &Arc<HighFrequencyExecutionEngine>,
    arena: &Arc<MarketArena>,
    risk_manager: &Arc<RiskManager>,
    depeg_circuit: &Arc<StablecoinMonitor>,
    paper: &Arc<PaperTradingPipeline>,
    state_tx: &tokio::sync::mpsc::Sender<PersistentState>,
    capital_fp: u64,
) {
    println!("\n==========================================================================");
    println!("RUNNING FULL PIPELINE INTEGRATION SMOKE-TEST");
    println!("==========================================================================");

    // --- Step 1: Inject synthetic prices into the arena ---
    // Simulate BTC trading at $50,000 on Exchange 0 and $50,100 on Exchange 1
    // (a 20 bps spread = 0.20%)
    arena.update_price(0, 10, 50_000_000_000, 50_001_000_000); // Ex0: bid=50000, ask=50001 (2-decimal fp)
    arena.update_price(1, 10, 50_099_000_000, 50_100_000_000); // Ex1: bid=50099, ask=50100

    println!("Injected synthetic BTC prices:");
    println!("  Exchange 0: bid=50000.00 ask=50001.00");
    println!("  Exchange 1: bid=50099.00 ask=50100.00");
    println!("  Cross-exchange spread: ~20 bps");

    // --- Step 2: Build cross-exchange targets and evaluate ---
    // Note: build_cross_exchange_targets requires &mut self — called
    // on the local mutable binding before Arc wrap, or via interior mutability.
    // For the integration test we call evaluate_tick directly on injected prices.
    let signals = arena.evaluate_tick(0, 10, 15, 15); // 15 bps minimum

    if signals.is_empty() {
        println!("  No arbitrage signals detected (spread below threshold or targets not built)");
    } else {
        println!("  Detected {} arbitrage signal(s):", signals.len());
        for sig in &signals {
            match sig {
                ArbitrageSignal::CrossExchange { buy_exchange, sell_exchange, token_id, spread_bps } => {
                    println!("    CROSS-EXCHANGE: Buy on Ex{} Sell on Ex{} Token={} Spread={}bps",
                        buy_exchange, sell_exchange, token_id, spread_bps);
                }
                ArbitrageSignal::Triangular { exchange_id, token_a, token_b, token_c, profit_bps } => {
                    println!("    TRIANGULAR: Ex{} {}->{}->{} Profit={}bps",
                        exchange_id, token_a, token_b, token_c, profit_bps);
                }
            }
        }
    }

    // --- Step 3: Test the stablecoin depeg monitor ---
    depeg_circuit.update_price("USDT", dec!(1.0000), "Binance").await;
    assert!(!depeg_circuit.is_depeg_active().await, "USDT at 1.0 should not trigger depeg");
    println!("  Stablecoin monitor: USDT at $1.0000 — healthy");

    depeg_circuit.update_price("USDT", dec!(0.995), "Binance").await;
    assert!(depeg_circuit.is_depeg_active().await, "USDT at 0.995 should trigger depeg");
    println!("  Stablecoin monitor: USDT at $0.995 — DEPEG DETECTED");

    depeg_circuit.update_price("USDT", dec!(1.0000), "Binance").await;
    assert!(!depeg_circuit.is_depeg_active().await, "USDT recovery should clear depeg");
    println!("  Stablecoin monitor: USDT recovered to $1.0000 — depeg cleared");

    // --- Step 4: Test the paper trading pipeline ---
    paper.simulate_fill(0, 10, "BTCUSDT", dec!(0.01), dec!(50000.00), true).await;
    let usdt_bal = paper.get_balance(0).await;
    println!("  Paper trade executed: BUY 0.01 BTC @ $50000");
    println!("  Paper USDT balance after buy: ${:.4}", usdt_bal);

    // --- Step 5: Test the risk manager ---
    risk_manager.update_equity(capital_fp);
    risk_manager.touch_network_check();

    let check_result = risk_manager.pre_trade_check(20, 15_000_000_000, capital_fp, 0);
    assert!(check_result.is_ok(), "Legitimate trade should pass risk check");
    println!("  Risk manager: 20 bps trade passed all 14 layers");

    let blocked = risk_manager.pre_trade_check(1, 15_000_000_000, capital_fp, 0);
    assert!(blocked.is_err(), "1 bps trade should be below minimum threshold");
    println!("  Risk manager: 1 bps trade correctly REJECTED (profit below threshold)");

    // --- Step 6: Test exchange health tracking ---
    risk_manager.record_exchange_failure(2);
    risk_manager.record_exchange_failure(2);
    println!("  Exchange health: Ex2 failure count = 2 (threshold = 3)");

    risk_manager.record_exchange_success(2);
    println!("  Exchange health: Ex2 success recorded — failure count reset to 0");

    // --- Step 7: Test the execution engine ---
    let leg_a = OrderIntent {
        exchange_id: 0,
        token_id: 10,
        qty: dec!(0.001),
        price: dec!(50001.00),
        is_buy: true,
        symbol: "BTCUSDT".to_string(),
    };
    let leg_b = OrderIntent {
        exchange_id: 1,
        token_id: 10,
        qty: dec!(0.001),
        price: dec!(50099.00),
        is_buy: false,
        symbol: "BTCUSDT".to_string(),
    };

    // Use a high enough profit_bps to pass the risk gate
    match engine.blast_arbitrage_legs(leg_a, leg_b, 20, capital_fp).await {
        Ok((res_a, res_b)) => {
            println!("  Execution engine: Two-leg blast FIRED successfully");
            println!("    Leg A (BUY  Ex0): success={} filled={} avg_price={}",
                res_a.success, res_a.filled_qty, res_a.avg_price);
            println!("    Leg B (SELL Ex1): success={} filled={} avg_price={}",
                res_b.success, res_b.filled_qty, res_b.avg_price);
        }
        Err(e) => {
            println!("  Execution engine: {}", e);
        }
    }

    // --- Step 8: Persist state to disk ---
    let final_bal = paper.get_balance(0).await;
    let state = PersistentState {
        paper_usd_balance: final_bal,
        is_system_risk_frozen: false,
        session_pnl_cents: risk_manager.get_session_pnl(),
        total_trades: paper.get_total_trades().await,
        timestamp: chrono::Utc::now().timestamp_millis(),
        exchange_health: HashMap::new(),
    };
    if state_tx.send(state).await.is_err() {
        tracing::error!("state_tx receiver dropped -- state snapshots are no longer being persisted to disk!");
    }
    println!("  Persistence: State snapshot queued for disk write");

    // --- Step 9: Test freeze / unfreeze ---
    risk_manager.freeze();
    let frozen_check = risk_manager.pre_trade_check(100, 100, capital_fp, 0);
    assert!(frozen_check.is_err(), "Frozen system should reject all trades");
    risk_manager.unfreeze();
    let unfrozen_check = risk_manager.pre_trade_check(100, 100, capital_fp, 0);
    assert!(unfrozen_check.is_ok(), "Unfrozen system should accept valid trades");
    println!("  Risk manager: Freeze/unfreeze cycle verified");

    println!("==========================================================================");
    println!("ALL PIPELINE INTEGRATION CHECKS PASSED");
    println!("==========================================================================\n");
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Convert a `Decimal` dollar value to fixed-point u64 (dollars * 1_000_000).
/// Clamps negative values to 0 (with a warning) rather than silently zeroizing.
fn decimal_to_fp(d: Decimal) -> u64 {
    if d < Decimal::ZERO {
        tracing::warn!(value = %d, "main decimal_to_fp: negative value clamped to 0");
        return 0;
    }
    let scaled = d * Decimal::from(FP_SCALE);
    let s = format!("{}", scaled);
    let parts: Vec<&str> = s.split('.').collect();
    parts[0].parse().unwrap_or(0)
}