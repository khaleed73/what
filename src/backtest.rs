// backtest.rs — Cross-Exchange Arbitrage Backtesting Engine.
//
// Loads historical price bar data (CSV), simulates cross-exchange arbitrage
// trades with configurable fees and spread thresholds, and computes
// performance metrics (P&L, drawdown, Sharpe ratio, win rate).
//
// ## Data Format
//
// CSV columns: `timestamp,exchange_id,symbol,bid_price,ask_price,volume_24h`
//
// ## Usage
//
// ```ignore
// let config = BacktestConfig::default();
// let result = run_backtest("data/bars.csv", config).await?;
// println!("Total P&L: {}", result.total_pnl);
// ```

use std::collections::HashMap;

use rust_decimal::Decimal;
use rust_decimal::prelude::ToPrimitive;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

// ═══════════════════════════════════════════════════════════════════════════
//  PriceBar
// ═══════════════════════════════════════════════════════════════════════════

/// A single price observation for one symbol on one exchange.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PriceBar {
    /// UNIX timestamp in milliseconds.
    pub timestamp: i64,
    /// Numeric exchange ID (see `exchange_name_by_id`).
    pub exchange_id: u16,
    /// Trading pair symbol (e.g. "BTCUSDT").
    pub symbol: String,
    /// Best bid price.
    pub bid_price: Decimal,
    /// Best ask price.
    pub ask_price: Decimal,
    /// 24h volume in base currency.
    pub volume_24h: Decimal,
}

// ═══════════════════════════════════════════════════════════════════════════
//  BacktestConfig
// ═══════════════════════════════════════════════════════════════════════════

/// Configuration for the backtesting engine.
#[derive(Debug, Clone)]
pub struct BacktestConfig {
    /// Starting capital in USD. Default: 100,000.
    pub initial_capital: Decimal,
    /// Maximum fraction of capital to deploy in a single trade. Default: 0.15.
    pub max_position_pct: Decimal,
    /// Taker fee in basis points. Default: 10 (0.10%).
    pub taker_fee_bps: u64,
    /// Minimum spread in basis points to act on. Default: 15 (0.15%).
    pub min_spread_bps: u64,
    /// Path to CSV file containing historical price bars.
    pub data_file: String,
}

impl Default for BacktestConfig {
    fn default() -> Self {
        Self {
            initial_capital: Decimal::from(100_000u64),
            max_position_pct: Decimal::from_str_radix("0.15", 10).unwrap_or(Decimal::new(15, 2)),
            taker_fee_bps: 10,
            min_spread_bps: 15,
            data_file: String::new(),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  BacktestTrade
// ═══════════════════════════════════════════════════════════════════════════

/// A completed simulated cross-exchange arbitrage trade.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BacktestTrade {
    /// Entry timestamp (unix millis).
    pub entry_time: i64,
    /// Exit timestamp (unix millis) — same as entry for instant arb.
    pub exit_time: i64,
    /// Trading pair symbol.
    pub symbol: String,
    /// Exchange where we bought (lower ask).
    pub buy_exchange: u16,
    /// Exchange where we sold (higher bid).
    pub sell_exchange: u16,
    /// Spread in basis points at entry.
    pub entry_spread_bps: u64,
    /// Quantity traded.
    pub qty: Decimal,
    /// Net P&L in USD.
    pub pnl: Decimal,
    /// Total round-trip fees in USD.
    pub fees: Decimal,
}

// ═══════════════════════════════════════════════════════════════════════════
//  BacktestResult
// ═══════════════════════════════════════════════════════════════════════════

/// Aggregated results from a backtest run.
#[derive(Debug, Clone)]
pub struct BacktestResult {
    /// Total net P&L in USD.
    pub total_pnl: Decimal,
    /// Total fees paid in USD.
    pub total_fees: Decimal,
    /// Total number of trades executed.
    pub total_trades: u64,
    /// Fraction of trades that were profitable (0.0–1.0).
    pub win_rate: Decimal,
    /// Maximum drawdown as a fraction (0.0–1.0).
    pub max_drawdown: Decimal,
    /// Annualized Sharpe ratio (risk-free rate assumed 0).
    pub sharpe_ratio: Decimal,
    /// Individual trade records.
    pub trades: Vec<BacktestTrade>,
}

impl BacktestResult {
    /// Pretty-print a summary of the backtest results.
    pub fn summary(&self) -> String {
        let mut lines = Vec::new();
        lines.push("═".repeat(60));
        lines.push("  BACKTEST RESULTS".to_string());
        lines.push("═".repeat(60));
        lines.push(format!("  Gross P&L:        ${:.2}", self.total_pnl + self.total_fees));
        lines.push(format!("  Total Fees:       ${:.2}", self.total_fees));
        lines.push(format!("  Net P&L:          ${:.2}", self.total_pnl));
        lines.push(format!("  Total Trades:     {}", self.total_trades));
        lines.push(format!("  Win Rate:         {:.2}%", self.win_rate * Decimal::from(100u64)));
        lines.push(format!("  Max Drawdown:     {:.2}%", self.max_drawdown * Decimal::from(100u64)));
        lines.push(format!("  Sharpe Ratio:     {:.4}", self.sharpe_ratio));
        lines.push("═".repeat(60));
        lines.join("\n")
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  BacktestEngine
// ═══════════════════════════════════════════════════════════════════════════

/// The main backtesting engine.
///
/// Simulates cross-exchange arbitrage on historical price data with
/// realistic fee deductions, position sizing, and capital tracking.
pub struct BacktestEngine {
    config: BacktestConfig,
    /// Current available capital in USD.
    capital: Decimal,
    /// Current open positions (symbol → qty).  In pure arb, positions
    /// are opened and closed simultaneously, so this is transient.
    positions: HashMap<String, Decimal>,
    /// All completed trades.
    trades: Vec<BacktestTrade>,
    /// Per-exchange USD balance tracking.
    exchange_balances: HashMap<u16, Decimal>,
    /// Loaded price bars (populated by `load_data`).
    bars: Vec<PriceBar>,
}

impl BacktestEngine {
    /// Create a new backtest engine with the given configuration.
    pub fn new(config: BacktestConfig) -> Self {
        Self {
            capital: config.initial_capital,
            positions: HashMap::new(),
            trades: Vec::new(),
            exchange_balances: HashMap::new(),
            bars: Vec::new(),
            config,
        }
    }

    /// Load price bars from a CSV file.
    ///
    /// Expected columns: `timestamp,exchange_id,symbol,bid_price,ask_price,volume_24h`
    ///
    /// Returns the number of bars loaded.
    pub async fn load_data(&mut self, path: &str) -> Result<usize, String> {
        // Read file content synchronously in a blocking context to avoid
        // polluting the async runtime.  For large files, use tokio::fs.
        let content = tokio::fs::read_to_string(path)
            .await
            .map_err(|e| format!("failed to read CSV '{}': {}", path, e))?;

        let mut count = 0usize;
        let mut lines = content.lines();

        // Skip header line.
        if let Some(header) = lines.next() {
            let header = header.trim();
            if !header.contains("timestamp") {
                warn!("CSV header does not contain 'timestamp': {}", header);
            }
        }

        for line in lines {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            match parse_price_bar(line) {
                Ok(bar) => {
                    count += 1;
                    self.bars.push(bar);
                }
                Err(e) => {
                    warn!("skipping malformed CSV line {}: {}", count + 1, e);
                    continue;
                }
            }
        }

        info!(path = path, bars = count, "Loaded price bars from CSV");
        Ok(count)
    }

    /// Run the backtest on bars previously loaded via `load_data`.
    pub fn run_loaded(&mut self) -> BacktestResult {
        self.run(self.bars.clone().as_slice())
    }

    /// Run the backtest on a slice of `PriceBar`s.
    ///
    /// # Algorithm
    ///
    /// 1. Group bars by timestamp.
    /// 2. For each timestamp snapshot, group bars by (symbol, exchange).
    /// 3. For each symbol, compare all exchange pairs:
    ///    - If `sell_bid - buy_ask > min_spread` (in bps), execute a trade.
    ///    - Deduct round-trip taker fees.
    ///    - Track capital, P&L, fees.
    /// 4. Compute final statistics.
    pub fn run(&mut self, bars: &[PriceBar]) -> BacktestResult {
        if bars.is_empty() {
            return BacktestResult {
                total_pnl: Decimal::ZERO,
                total_fees: Decimal::ZERO,
                total_trades: 0,
                win_rate: Decimal::ZERO,
                max_drawdown: Decimal::ZERO,
                sharpe_ratio: Decimal::ZERO,
                trades: Vec::new(),
            };
        }

        // Initialize per-exchange balances evenly.
        let mut seen_exchanges: Vec<u16> = bars
            .iter()
            .map(|b| b.exchange_id)
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        seen_exchanges.sort();
        let num_exchanges = seen_exchanges.len().max(1);
        let per_exchange_capital = self.capital / Decimal::from(num_exchanges as u64);

        for &ex_id in &seen_exchanges {
            self.exchange_balances.insert(ex_id, per_exchange_capital);
        }

        info!(
            exchanges = seen_exchanges.len(),
            initial_capital = %self.capital,
            per_exchange = %per_exchange_capital,
            min_spread_bps = self.config.min_spread_bps,
            taker_fee_bps = self.config.taker_fee_bps,
            "Starting backtest"
        );

        // Group bars by timestamp.
        let mut time_groups: HashMap<i64, Vec<&PriceBar>> = HashMap::new();
        for bar in bars {
            time_groups
                .entry(bar.timestamp)
                .or_default()
                .push(bar);
        }

        // Sort timestamps chronologically.
        let mut timestamps: Vec<i64> = time_groups.keys().copied().collect();
        timestamps.sort();

        let fee_fraction = Decimal::from(self.config.taker_fee_bps) / Decimal::from(10_000u64);
        let _min_spread_decimal =
            Decimal::from(self.config.min_spread_bps) / Decimal::from(10_000u64);

        // Track equity curve for drawdown and Sharpe.
        let mut equity_curve: Vec<Decimal> = vec![self.capital];

        for &ts in &timestamps {
            let snapshot = match time_groups.get(&ts) {
                Some(s) => s,
                None => continue,
            };

            // Group by symbol.
            let mut by_symbol: HashMap<&str, Vec<&PriceBar>> = HashMap::new();
            for bar in snapshot {
                by_symbol.entry(&bar.symbol).or_default().push(bar);
            }

            // For each symbol, check all exchange pairs for arb opportunity.
            for (symbol, symbol_bars) in &by_symbol {
                if symbol_bars.len() < 2 {
                    continue;
                }

                // Build a map: exchange_id -> (bid, ask).
                let mut market_map: HashMap<u16, (Decimal, Decimal)> = HashMap::new();
                for bar in symbol_bars {
                    market_map.insert(bar.exchange_id, (bar.bid_price, bar.ask_price));
                }

                let exchanges: Vec<u16> = market_map.keys().copied().collect();

                // Compare every pair.
                for i in 0..exchanges.len() {
                    for j in (i + 1)..exchanges.len() {
                        let ex_a = exchanges[i];
                        let ex_b = exchanges[j];

                        let (bid_a, ask_a) = market_map[&ex_a];
                        let (bid_b, ask_b) = market_map[&ex_b];

                        // Strategy 1: Buy on A, Sell on B
                        // Spread = bid_b - ask_a (as fraction of mid price)
                        if ask_a > Decimal::ZERO && bid_b > ask_a {
                            let mid = (ask_a + bid_b) / Decimal::TWO;
                            let spread = (bid_b - ask_a) / mid;
                            let spread_bps = (spread * Decimal::from(10_000u64))
                                .to_u64()
                                .unwrap_or(0);

                            if spread_bps >= self.config.min_spread_bps {
                                let buy_price = ask_a;
                                let sell_price = bid_b;

                                // Calculate position size.
                                // Max position = capital * max_position_pct.
                                // We need capital on both exchanges.
                                let bal_a = self
                                    .exchange_balances
                                    .get(&ex_a)
                                    .copied()
                                    .unwrap_or(Decimal::ZERO);
                                let bal_b = self
                                    .exchange_balances
                                    .get(&ex_b)
                                    .copied()
                                    .unwrap_or(Decimal::ZERO);

                                let max_buy_capital = bal_a * self.config.max_position_pct;
                                let qty = if buy_price > Decimal::ZERO {
                                    (max_buy_capital / buy_price).floor()
                                } else {
                                    Decimal::ZERO
                                };

                                if qty <= Decimal::ZERO {
                                    continue;
                                }

                                let buy_cost = qty * buy_price;
                                let sell_proceeds = qty * sell_price;
                                let buy_fee = buy_cost * fee_fraction;
                                let sell_fee = sell_proceeds * fee_fraction;
                                let total_fees = buy_fee + sell_fee;
                                let gross_pnl = sell_proceeds - buy_cost;
                                let net_pnl = gross_pnl - total_fees;

                                // Only execute if net P&L is positive.
                                if net_pnl > Decimal::ZERO && buy_cost <= bal_a {
                                    let trade = BacktestTrade {
                                        entry_time: ts,
                                        exit_time: ts,
                                        symbol: (*symbol).to_string(),
                                        buy_exchange: ex_a,
                                        sell_exchange: ex_b,
                                        entry_spread_bps: spread_bps,
                                        qty,
                                        pnl: net_pnl,
                                        fees: total_fees,
                                    };

                                    // Update balances.
                                    let new_bal_a = bal_a - buy_cost - buy_fee;
                                    let new_bal_b = bal_b + sell_proceeds - sell_fee;
                                    self.exchange_balances.insert(ex_a, new_bal_a);
                                    self.exchange_balances.insert(ex_b, new_bal_b);

                                    self.capital = self
                                        .exchange_balances
                                        .values()
                                        .copied()
                                        .sum();

                                    self.trades.push(trade);
                                    equity_curve.push(self.capital);
                                }
                            }
                        }

                        // Strategy 2: Buy on B, Sell on A
                        if ask_b > Decimal::ZERO && bid_a > ask_b {
                            let mid = (ask_b + bid_a) / Decimal::TWO;
                            let spread = (bid_a - ask_b) / mid;
                            let spread_bps = (spread * Decimal::from(10_000u64))
                                .to_u64()
                                .unwrap_or(0);

                            if spread_bps >= self.config.min_spread_bps {
                                let buy_price = ask_b;
                                let sell_price = bid_a;

                                let bal_b = self
                                    .exchange_balances
                                    .get(&ex_b)
                                    .copied()
                                    .unwrap_or(Decimal::ZERO);
                                let bal_a = self
                                    .exchange_balances
                                    .get(&ex_a)
                                    .copied()
                                    .unwrap_or(Decimal::ZERO);

                                let max_buy_capital = bal_b * self.config.max_position_pct;
                                let qty = if buy_price > Decimal::ZERO {
                                    (max_buy_capital / buy_price).floor()
                                } else {
                                    Decimal::ZERO
                                };

                                if qty <= Decimal::ZERO {
                                    continue;
                                }

                                let buy_cost = qty * buy_price;
                                let sell_proceeds = qty * sell_price;
                                let buy_fee = buy_cost * fee_fraction;
                                let sell_fee = sell_proceeds * fee_fraction;
                                let total_fees = buy_fee + sell_fee;
                                let gross_pnl = sell_proceeds - buy_cost;
                                let net_pnl = gross_pnl - total_fees;

                                if net_pnl > Decimal::ZERO && buy_cost <= bal_b {
                                    let trade = BacktestTrade {
                                        entry_time: ts,
                                        exit_time: ts,
                                        symbol: (*symbol).to_string(),
                                        buy_exchange: ex_b,
                                        sell_exchange: ex_a,
                                        entry_spread_bps: spread_bps,
                                        qty,
                                        pnl: net_pnl,
                                        fees: total_fees,
                                    };

                                    let new_bal_b = bal_b - buy_cost - buy_fee;
                                    let new_bal_a = bal_a + sell_proceeds - sell_fee;
                                    self.exchange_balances.insert(ex_b, new_bal_b);
                                    self.exchange_balances.insert(ex_a, new_bal_a);

                                    self.capital = self
                                        .exchange_balances
                                        .values()
                                        .copied()
                                        .sum();

                                    self.trades.push(trade);
                                    equity_curve.push(self.capital);
                                }
                            }
                        }
                    }
                }
            }
        }

        // ── Compute aggregate statistics ─────────────────────────────────
        let total_pnl: Decimal = self.trades.iter().map(|t| t.pnl).sum();
        let total_fees: Decimal = self.trades.iter().map(|t| t.fees).sum();
        let total_trades = self.trades.len() as u64;

        let winning_trades = self
            .trades
            .iter()
            .filter(|t| t.pnl > Decimal::ZERO)
            .count() as u64;
        let win_rate = if total_trades > 0 {
            Decimal::from(winning_trades) / Decimal::from(total_trades)
        } else {
            Decimal::ZERO
        };

        // Max drawdown.
        let max_drawdown = compute_max_drawdown(&equity_curve);

        // Sharpe ratio (annualized, assuming ~365 days of data).
        let sharpe_ratio = compute_sharpe_ratio(&equity_curve, 365);

        info!(
            total_pnl = %total_pnl,
            total_fees = %total_fees,
            total_trades = total_trades,
            win_rate = %win_rate,
            max_drawdown = %max_drawdown,
            sharpe = %sharpe_ratio,
            "Backtest complete"
        );

        BacktestResult {
            total_pnl,
            total_fees,
            total_trades,
            win_rate,
            max_drawdown,
            sharpe_ratio,
            trades: std::mem::take(&mut self.trades),
        }
    }

    /// Generate a sample CSV file with synthetic price data for testing.
    ///
    /// Creates `num_bars` rows across 3 exchanges and 2 symbols with
    /// realistic price movements and occasional arb spreads.
    pub fn generate_sample_csv(path: &str, num_bars: usize) {
        use std::io::Write;

        let mut file = match std::fs::File::create(path) {
            Ok(f) => f,
            Err(e) => {
                tracing::error!("failed to create sample CSV '{}': {}", path, e);
                return;
            }
        };

        // Header.
        let _ = writeln!(
            file,
            "timestamp,exchange_id,symbol,bid_price,ask_price,volume_24h"
        );

        let base_ts = 1_700_000_000_000i64; // Nov 2023
        let exchanges = [0u16, 1u16, 2u16]; // Binance, Bybit, OKX
        let symbols = ["BTCUSDT", "ETHUSDT"];
        let base_prices: HashMap<&str, Decimal> =
            [("BTCUSDT", dec(43000.0)), ("ETHUSDT", dec(2280.0))]
                .iter()
                .copied()
                .collect();

        // Simple pseudo-random using a linear congruential generator.
        let mut seed: u64 = 42;
        let mut next_rand = move || -> f64 {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            (seed >> 33) as f64 / (1u64 << 31) as f64
        };

        // Spread injection probability (5% of bars get an arb spread).
        let spread_inject_prob = 0.05;

        for i in 0..num_bars {
            let ts = base_ts + (i as i64 * 1000); // 1-second intervals
            let ex_idx = i % exchanges.len();
            let sym_idx = i % symbols.len();
            let exchange_id = exchanges[ex_idx];
            let symbol = symbols[sym_idx];

            let base = base_prices[symbol];

            // Random walk: ±0.05% per tick with mean reversion.
            let noise = (next_rand() - 0.5) * 0.001;
            let base_ref_price = dec(43000.0) + Decimal::from(sym_idx as u64 * 2000);
            let mean_reversion = (base - base_ref_price)
                * Decimal::from_str_radix("0.0001", 10).unwrap_or(Decimal::ZERO);
            let adj_noise = Decimal::from_f64_retain(noise).unwrap_or(Decimal::ZERO);
            let price = base * (Decimal::ONE + adj_noise) + mean_reversion;

            // Normal bid-ask spread: ~1-2 bps.
            let normal_spread_bps = 1.0 + next_rand() * 1.0;
            let half_spread = price
                * Decimal::from_f64_retain(normal_spread_bps * 0.5 / 10000.0)
                    .unwrap_or(Decimal::ZERO);

            let (bid, ask) = if next_rand() < spread_inject_prob {
                // Inject an arb-eligible spread: 20-50 bps.
                let arb_spread = price
                    * Decimal::from_f64_retain((20.0 + next_rand() * 30.0) / 10000.0)
                        .unwrap_or(Decimal::ZERO);
                // 50/50 chance of being the cheap or expensive side.
                if ex_idx == 0 {
                    (price - arb_spread / Decimal::TWO, price - arb_spread / Decimal::TWO + half_spread)
                } else if ex_idx == 1 {
                    (price + arb_spread / Decimal::TWO - half_spread, price + arb_spread / Decimal::TWO)
                } else {
                    // Random wide spread on OKX.
                    (price - half_spread * Decimal::from(5u64), price + half_spread * Decimal::from(5u64))
                }
            } else {
                (price - half_spread, price + half_spread)
            };

            let volume = Decimal::from_f64_retain(1_000_000.0 + next_rand() * 10_000_000.0)
                .unwrap_or(Decimal::ONE);

            let _ = writeln!(
                file,
                "{},{},{},{:.2},{:.2},{:.2}",
                ts, exchange_id, symbol, bid, ask, volume
            );
        }

        info!(path = path, bars = num_bars, "Generated sample CSV");
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  Convenience function
// ═══════════════════════════════════════════════════════════════════════════

/// Load data from `data_file` and run the backtest with the given config.
///
/// Returns the aggregated `BacktestResult`.
pub async fn run_backtest(
    data_file: &str,
    config: BacktestConfig,
) -> Result<BacktestResult, String> {
    let content = tokio::fs::read_to_string(data_file)
        .await
        .map_err(|e| format!("failed to read '{}': {}", data_file, e))?;

    let bars = parse_csv_bars(&content)?;
    info!(
        path = data_file,
        total_bars = bars.len(),
        "Loaded bars for backtest"
    );

    let mut engine = BacktestEngine::new(config);
    let result = engine.run(&bars);
    Ok(result)
}

// ═══════════════════════════════════════════════════════════════════════════
//  Internal helpers
// ═══════════════════════════════════════════════════════════════════════════

/// Parse a single CSV line into a `PriceBar`.
fn parse_price_bar(line: &str) -> Result<PriceBar, String> {
    let parts: Vec<&str> = line.split(',').collect();
    if parts.len() != 6 {
        return Err(format!("expected 6 columns, got {}", parts.len()));
    }

    let timestamp = parts[0]
        .trim()
        .parse::<i64>()
        .map_err(|e| format!("invalid timestamp '{}': {}", parts[0], e))?;

    let exchange_id = parts[1]
        .trim()
        .parse::<u16>()
        .map_err(|e| format!("invalid exchange_id '{}': {}", parts[1], e))?;

    let symbol = parts[2].trim().to_string();

    let bid_price = parts[3]
        .trim()
        .parse::<Decimal>()
        .map_err(|e| format!("invalid bid_price '{}': {}", parts[3], e))?;

    let ask_price = parts[4]
        .trim()
        .parse::<Decimal>()
        .map_err(|e| format!("invalid ask_price '{}': {}", parts[4], e))?;

    let volume_24h = parts[5]
        .trim()
        .parse::<Decimal>()
        .map_err(|e| format!("invalid volume_24h '{}': {}", parts[5], e))?;

    Ok(PriceBar {
        timestamp,
        exchange_id,
        symbol,
        bid_price,
        ask_price,
        volume_24h,
    })
}

/// Parse all CSV lines (skipping header) into a `Vec<PriceBar>`.
fn parse_csv_bars(content: &str) -> Result<Vec<PriceBar>, String> {
    let mut bars = Vec::new();
    let mut lines = content.lines();

    // Skip header.
    let _ = lines.next();

    for (i, line) in lines.enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        match parse_price_bar(line) {
            Ok(bar) => bars.push(bar),
            Err(e) => {
                warn!("skipping CSV line {}: {}", i + 2, e);
            }
        }
    }

    Ok(bars)
}

/// Compute maximum drawdown from an equity curve.
///
/// Drawdown is defined as `(peak - trough) / peak` and the function
/// returns the maximum observed drawdown across the entire curve.
fn compute_max_drawdown(equity_curve: &[Decimal]) -> Decimal {
    if equity_curve.is_empty() {
        return Decimal::ZERO;
    }

    let mut peak = equity_curve[0];
    let mut max_dd = Decimal::ZERO;

    for &value in equity_curve {
        if value > peak {
            peak = value;
        }
        if peak > Decimal::ZERO {
            let dd = (peak - value) / peak;
            if dd > max_dd {
                max_dd = dd;
            }
        }
    }

    max_dd
}

/// Compute annualized Sharpe ratio from an equity curve.
///
/// Assumes risk-free rate = 0. Uses per-step returns and annualizes
/// by multiplying by `sqrt(annual_steps)`.
fn compute_sharpe_ratio(equity_curve: &[Decimal], annual_steps: u64) -> Decimal {
    if equity_curve.len() < 2 {
        return Decimal::ZERO;
    }

    // Compute per-step returns.
    let mut returns: Vec<Decimal> = Vec::new();
    for i in 1..equity_curve.len() {
        let prev = equity_curve[i - 1];
        if prev > Decimal::ZERO {
            let ret = (equity_curve[i] - prev) / prev;
            returns.push(ret);
        }
    }

    if returns.is_empty() {
        return Decimal::ZERO;
    }

    // Mean return.
    let sum: Decimal = returns.iter().copied().sum();
    let n = Decimal::from(returns.len() as u64);
    let mean = sum / n;

    // Standard deviation.
    let variance: Decimal = returns
        .iter()
        .map(|r| {
            let diff = *r - mean;
            diff * diff
        })
        .sum::<Decimal>()
        / n;

    let std_dev = if variance >= Decimal::ZERO {
        decimal_sqrt(variance, 20)
    } else {
        Decimal::ZERO
    };

    if std_dev == Decimal::ZERO {
        return Decimal::ZERO;
    }

    // Annualized: Sharpe = (mean / std_dev) * sqrt(annual_steps)
    let raw_sharpe = mean / std_dev;

    // sqrt(annual_steps) approximation using Newton's method.
    let annual_factor = decimal_sqrt(Decimal::from(annual_steps), 20);

    raw_sharpe * annual_factor
}

/// Compute square root of a `Decimal` using Newton's method.
///
/// `iterations` controls precision.  20 iterations is sufficient for
/// financial calculations.
fn decimal_sqrt(value: Decimal, iterations: usize) -> Decimal {
    if value <= Decimal::ZERO {
        return Decimal::ZERO;
    }

    let mut guess = value / Decimal::TWO;
    for _ in 0..iterations {
        if guess == Decimal::ZERO {
            break;
        }
        guess = (guess + value / guess) / Decimal::TWO;
    }
    guess
}

/// `dec!` macro helper for inline decimal literals.
/// Mirrors `rust_decimal_macros::dec!` but as a function to avoid
/// requiring the macro crate.
fn dec(value: f64) -> Decimal {
    Decimal::from_f64_retain(value).unwrap_or(Decimal::ZERO)
}