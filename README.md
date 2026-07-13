# rust-hft-arb

High-frequency cross-exchange and triangular arbitrage bot with a 14-layer risk management system, built in Rust.

## Architecture

```
WebSocket Feeds ──► Zero-Alloc Parser ──► Atomic Price Matrix (MarketArena)
                                                    │
                                        ┌───────────┴───────────┐
                                        ▼                       ▼
                               Cross-Exchange Arb         Triangular Arb
                                        │                       │
                                        └───────────┬───────────┘
                                                    ▼
                                          14-Layer Risk Gatekeeper
                                                    │
                                                    ▼
                                          Execution Engine
                                         ┌─────────┴─────────┐
                                         ▼                   ▼
                                   Paper Pipeline      Real Pipeline
                                                        (typed clients)
                                                            │
                                                    ┌───────┴───────┐
                                                    ▼               ▼
                                               Binance/Bybit    OKX/KuCoin
                                               GateIO/HTX      BitMEX/etc.
```

### Core Design Principles

- **Lock-free hot path**: All price updates, signal detection, and risk checks use `AtomicU64`/`AtomicBool` with `Release`/`Acquire` ordering — no mutexes, no locks.
- **Zero-allocation parsing**: `parse_raw_bytes_fast()` manually scans raw WebSocket bytes without `serde_json` or heap allocation.
- **Fixed-point arithmetic**: Monetary values use `u64` with `FP_SCALE = 1_000_000` on the hot path and `rust_decimal::Decimal` everywhere else. No `f64` in financial calculations.
- **Actor-style workers**: Every subsystem (Discord, persistence, rebalancer, coin finder) runs as a long-lived tokio task communicating via MPSC channels.
- **CPU pinning**: Binds computation to a dedicated CPU core via `core_affinity`.

### 14-Layer Risk System

| Layer | Name | Purpose |
|-------|------|---------|
| 1 | Kill Switch | Global manual / automated shutdown |
| 2 | Min Profit Filter | Reject signals below configurable bps threshold |
| 3 | Network Staleness | Halt if no price update in N seconds |
| 4 | Equity Drawdown | Pause on session drawdown exceeding % cap |
| 5 | Hard Loss Cap | Absolute dollar loss circuit breaker |
| 6 | Stablecoin Depeg | Halt if USDT/USDC/DAI deviate from peg |
| 7 | Max Exposure | Limit total open notional as % of equity |
| 8 | Single Position | Cap per-token position size |
| 9 | Exchange Circuit Breaker | Auto-pause exchanges after N failures |
| 10 | Memecoin Filter | Block known high-volatility / low-liquidity tokens |
| 11 | Volume Filter | Require minimum 24h volume |
| 12 | Spread Sanity | Reject implausibly wide spreads |
| 13 | Latency Guard | Timeout signals older than max latency |
| 14 | Rate Limiter | Throttle order submission per exchange |

## Supported Exchanges (12)

Binance, Bybit, OKX, Gate.io, KuCoin, Bitfinex, Bitget, BitMEX, Coinbase, HTX (Huobi), Kraken, LBank

## Quick Start

### Prerequisites

- Rust 1.75+ (edition 2021)
- A VPS or bare-metal server with low-latency exchange connectivity

### Configuration

1. Copy the example config:
   ```bash
   cp config.toml.example config.toml
   ```

2. Edit `config.toml` with your exchange API credentials, strategy parameters, and risk limits.

3. Optionally set environment variables in `.env`:
   ```
   DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/...
   ```

### Running

```bash
# Build in release mode (LTO + codegen-units=1 + panic=abort)
cargo build --release

# Run (auto-detects placeholder keys and enters paper mode)
./target/release/rust-hft-arb
```

The bot automatically detects placeholder API keys and forces paper-trading mode. No real orders will be submitted until you configure valid credentials.

### Paper Trading Mode

By default, if any configured exchange has placeholder API keys, the engine runs in paper mode with simulated slippage (1-5 bps). All trades are virtual and tracked in memory.

### Metrics

The bot exposes a Prometheus-compatible `/metrics` endpoint on port **9090** by default:

```bash
curl http://localhost:9090/metrics
```

Available metrics:
- `rust_hft_arb_uptime_seconds` — Engine uptime
- `rust_hft_arb_signals_total` — Total arbitrage signals generated
- `rust_hft_arb_trades_total` — Total trades executed
- `rust_hft_arb_errors_total` — Total trade errors
- `rust_hft_arb_session_pnl_usd` — Current session P&L
- `rust_hft_arb_killswitch_active` — Whether the kill switch is active
- `rust_hft_arb_rollback_total` — Emergency counter-order rollbacks
- `rust_hft_arb_healthy` — System health status (1/0)

### Integration Tests & Benchmarks

```bash
# Connectivity test for all 12 exchanges
cargo run --bin connectivity_test

# Full pipeline test with real exchange data
cargo run --bin e2e_pipeline_test

# Microsecond-level latency benchmark
cargo run --bin pipeline_benchmark

# Unit tests (104 tests)
cargo test
```

## Project Structure

```
src/
├── main.rs              # Bootstrapper — wires all subsystems together
├── lib.rs               # Library target for integration tests
├── configs.rs           # TOML config parser & two-tier validator
├── strategies.rs        # Cross-exchange + triangular signal detection
├── protections.rs       # 14-layer risk gatekeeper (lock-free hot path)
├── execution.rs         # Order execution engine with retry & rollback
├── datafeed.rs          # WebSocket listener + zero-alloc byte parser
├── signer.rs            # HMAC-SHA256 signing + typed exchange clients
├── exchanges.rs         # HFT-specific exchange wrappers
├── stablecoin.rs        # Stablecoin depeg monitor (Decimal arithmetic)
├── health.rs            # Health monitoring with atomic counters
├── metrics.rs           # Prometheus /metrics HTTP endpoint
├── persistence.rs       # Atomic state file persistence
├── rebalancer.rs        # Auto inter-exchange capital rebalancer
├── paper_trading.rs     # In-memory paper trading simulator
├── discord.rs           # Non-blocking Discord webhook worker
├── balance_allocator.rs # Atomic balance matrix
├── coin_finder.rs       # Live coin/symbol scanner
└── exchange/            # Rich Exchange trait framework (12 implementations)
    ├── mod.rs, types.rs, exchange_trait.rs, config.rs, common.rs
    ├── binance.rs, bybit.rs, okx.rs, gateio.rs, kucoin.rs
    ├── bitfinex.rs, bitget.rs, bitmex.rs, coinbase.rs
    ├── htx.rs, kraken.rs, lbank.rs
    └── lbank.rs
```

## Security

- API keys in `config.toml` are gitignored (`.gitignore` excludes `config.toml`)
- Secrets wrapped in `SecretString` (backed by `secrecy` crate) — memory is zeroed on drop
- Debug output redacts all credentials
- `panic = "abort"` in release profile — no unwinding information leaks
- Atomic state file writes (write-to-tmp + rename) prevent corruption

## License

Proprietary. All rights reserved.