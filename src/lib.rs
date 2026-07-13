// lib.rs — Library target for rust-hft-arb.
//
// Exposes modules needed by integration tests and E2E test binaries.

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