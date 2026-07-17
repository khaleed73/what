// lib.rs — Library target for rust-hft-arb.
//
// Exposes modules needed by integration tests and E2E test binaries.

#![allow(dead_code)]

pub mod exchange;
pub mod strategies;
pub mod protections;
pub mod configs;
pub mod execution;
pub mod stablecoin;
pub mod health;
pub mod metrics;
pub mod signer;
pub mod balance_allocator;
pub mod persistence;
pub mod rebalancer;
pub mod paper_trading;
pub mod datafeed;
pub mod discord;
pub mod coin_finder;
pub mod order_book;
pub mod pnl_report;
pub mod dynamic_fees;
pub mod withdrawal;
pub mod backtest;
pub mod subaccount;
pub mod risk_shield;
pub mod safety_execution;
pub mod exchange_constraints;
pub mod atomic_orderbook;
pub mod circuit_breaker;
pub mod core_execution_shield;
pub mod ring_buffer_logger;
pub mod rebalance_matrix;
pub mod zero_alloc_signer;
pub mod zero_lag_stream;
pub mod cross_exchange_executor;
pub mod order_feed;
pub mod depeg_protection;
pub mod rate_limiter;
pub mod nonce_manager;
pub mod timestamp_sync;
pub mod shared_memory;
pub mod payload_arena;
pub mod size_slicer;
pub mod capital_starvation;
pub mod dust_manager;
pub mod private_ws_feed;
pub mod volatility_guard;
pub mod tcp_optimizer;
pub mod tri_path_finder;
pub mod production_risk_shield;
pub mod market_arena;
pub mod zero_copy_parser;
pub mod cpu_pinning;
pub mod live_order_tracker;