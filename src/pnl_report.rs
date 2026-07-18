//! Historical P&L Reporting Module
//!
//! Provides trade logging, P&L computation, and reporting for the HFT
//! arbitrage engine. Trades are persisted in JSONL format (one JSON object per
//! line) which is append-friendly and crash-safe.
//!
//! # Usage
//!
//! ```ignore
//! let trade_log = Arc::new(TradeLog::new("trade_log.jsonl".into()));
//! trade_log.load_existing().await;
//! trade_log.record_arb_pair(
//!     0, 1, "BTCUSDT", dec!(0.01), dec!(65000.0), dec!(65010.0),
//!     dec!(0.065), dec!(0.065), dec!(0.005),
//! ).await;
//! let report = trade_log.generate_report().await;
//! trade_log.print_summary().await;
//! ```

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use chrono::{TimeZone, Utc};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use tracing::{error, info};

use crate::exchange::exchange_name_by_id;

// ═══════════════════════════════════════════════════════════════════════════
//  TradeRecord
// ═══════════════════════════════════════════════════════════════════════════

/// A single recorded trade (one leg of a strategy execution).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TradeRecord {
    /// UUID v4 uniquely identifying this trade leg.
    pub trade_id: String,
    /// Unix timestamp in milliseconds.
    pub timestamp: i64,
    /// Numeric exchange identifier (e.g. 0 = Binance).
    pub exchange_id: u16,
    /// Human-readable exchange name (e.g. "Binance").
    pub exchange_name: String,
    /// Trading pair symbol (e.g. "BTCUSDT").
    pub symbol: String,
    /// Trade direction: "BUY" or "SELL".
    pub side: String,
    /// Filled quantity.
    pub quantity: Decimal,
    /// Fill price.
    pub price: Decimal,
    /// Trading fee charged (in quote currency).
    pub fee: Decimal,
    /// Realized P&L for this leg. `None` for open or first legs of a pair.
    pub pnl_realized: Option<Decimal>,
    /// Strategy that generated this trade: "cross_exchange" or "triangular".
    pub strategy: String,
    /// For cross-exchange arbs: the `trade_id` of the paired leg.
    pub pair_trade_id: Option<String>,
}

// ═══════════════════════════════════════════════════════════════════════════
//  PnlReport
// ═══════════════════════════════════════════════════════════════════════════

/// Aggregated P&L report generated from the full trade history.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PnlReport {
    /// All trades included in the report window.
    pub trades: Vec<TradeRecord>,
    /// Sum of all realized P&L across trades.
    pub total_pnl: Decimal,
    /// Sum of all fees paid.
    pub total_fees: Decimal,
    /// Sum of `quantity * price` for every trade.
    pub total_volume: Decimal,
    /// Number of trades with positive realized P&L.
    pub win_count: u64,
    /// Number of trades with negative realized P&L.
    pub loss_count: u64,
    /// Daily breakdown: ISO date string ("2025-01-15") → net P&L for that day.
    pub daily_pnl: BTreeMap<String, Decimal>,
}

// ═══════════════════════════════════════════════════════════════════════════
//  TradeLog — persistent trade logger
// ═══════════════════════════════════════════════════════════════════════════

/// Persistent trade logger backed by a JSONL file.
///
/// Thread-safe via `Arc<Mutex<…>>`. Every trade is immediately appended to
/// the JSONL file so no data is lost on crash.
pub struct TradeLog {
    /// In-memory trade record store.
    pub records: Arc<Mutex<Vec<TradeRecord>>>,
    /// Path to the JSONL file on disk.
    pub file_path: String,
}

impl TradeLog {
    /// Create a new `TradeLog` writing to the given file path.
    pub fn new(file_path: String) -> Self {
        Self {
            records: Arc::new(Mutex::new(Vec::new())),
            file_path,
        }
    }

    // -----------------------------------------------------------------------
    //  Core recording methods
    // -----------------------------------------------------------------------

    /// Record a single trade leg, append to the JSONL file.
    #[allow(clippy::too_many_arguments)]
    pub async fn record_trade(
        &self,
        exchange_id: u16,
        symbol: &str,
        side: &str,
        quantity: Decimal,
        price: Decimal,
        fee: Decimal,
        pnl_realized: Option<Decimal>,
        strategy: &str,
        pair_trade_id: Option<String>,
    ) {
        let record = TradeRecord {
            trade_id: uuid::Uuid::new_v4().to_string(),
            timestamp: chrono::Utc::now().timestamp_millis(),
            exchange_id,
            exchange_name: exchange_name_by_id(exchange_id).to_string(),
            symbol: symbol.to_string(),
            side: side.to_string(),
            quantity,
            price,
            fee,
            pnl_realized,
            strategy: strategy.to_string(),
            pair_trade_id,
        };

        // Append to in-memory store.
        {
            let mut records = self.records.lock().unwrap_or_else(|e| e.into_inner());
            records.push(record.clone());
        }

        // Append to JSONL file.
        if let Err(e) = self.append_to_file(&record) {
            error!(file = %self.file_path, error = %e, "Failed to append trade to JSONL file");
        }

        info!(
            trade_id = %record.trade_id,
            exchange = %record.exchange_name,
            symbol = %record.symbol,
            side = %record.side,
            qty = %record.quantity,
            price = %record.price,
            fee = %record.fee,
            pnl = ?record.pnl_realized,
            "Trade recorded"
        );
    }

    /// Record both legs of a cross-exchange arbitrage pair with computed P&L.
    ///
    /// The P&L is: `sell_qty * sell_price - buy_qty * buy_price - buy_fee - sell_fee`.
    /// This assumes the buy and sell quantities are equal (same coin).
    #[allow(clippy::too_many_arguments)]
    pub async fn record_arb_pair(
        &self,
        buy_exchange_id: u16,
        sell_exchange_id: u16,
        symbol: &str,
        quantity: Decimal,
        buy_price: Decimal,
        sell_price: Decimal,
        buy_fee: Decimal,
        sell_fee: Decimal,
    ) {
        let buy_trade_id = uuid::Uuid::new_v4().to_string();
        let sell_trade_id = uuid::Uuid::new_v4().to_string();
        let now = chrono::Utc::now().timestamp_millis();

        let gross_revenue = quantity * sell_price;
        let gross_cost = quantity * buy_price;
        let total_fees = buy_fee + sell_fee;
        let pnl = gross_revenue - gross_cost - total_fees;

        let buy_record = TradeRecord {
            trade_id: buy_trade_id.clone(),
            timestamp: now,
            exchange_id: buy_exchange_id,
            exchange_name: exchange_name_by_id(buy_exchange_id).to_string(),
            symbol: symbol.to_string(),
            side: "BUY".to_string(),
            quantity,
            price: buy_price,
            fee: buy_fee,
            pnl_realized: None, // opening leg — no realized P&L until close
            strategy: "cross_exchange".to_string(),
            pair_trade_id: Some(sell_trade_id.clone()),
        };

        let sell_record = TradeRecord {
            trade_id: sell_trade_id.clone(),
            timestamp: now,
            exchange_id: sell_exchange_id,
            exchange_name: exchange_name_by_id(sell_exchange_id).to_string(),
            symbol: symbol.to_string(),
            side: "SELL".to_string(),
            quantity,
            price: sell_price,
            fee: sell_fee,
            pnl_realized: Some(pnl), // closing leg — record full pair P&L
            strategy: "cross_exchange".to_string(),
            pair_trade_id: Some(buy_trade_id.clone()),
        };

        {
            let mut records = self.records.lock().unwrap_or_else(|e| e.into_inner());
            if let Err(e) = self.append_to_file(&buy_record) {
                error!(file = %self.file_path, error = %e, "Failed to append buy leg to JSONL");
            }
            if let Err(e) = self.append_to_file(&sell_record) {
                error!(file = %self.file_path, error = %e, "Failed to append sell leg to JSONL");
            }
            records.push(buy_record);
            records.push(sell_record);
        }

        info!(
            symbol = %symbol,
            buy_ex = %exchange_name_by_id(buy_exchange_id),
            sell_ex = %exchange_name_by_id(sell_exchange_id),
            qty = %quantity,
            buy_price = %buy_price,
            sell_price = %sell_price,
            pnl = %pnl,
            "Cross-exchange arb pair recorded"
        );
    }

    /// Record all 3 legs of a triangular arbitrage loop with computed loop P&L.
    ///
    /// A triangular arb cycles through 3 pairs on the same exchange:
    ///   1. Base → Intermediary (e.g. USDT → BTC)
    ///   2. Intermediary → Quote (e.g. BTC → ETH)
    ///   3. Quote → Base (e.g. ETH → USDT)
    ///
    /// The P&L is: final_base_amount - initial_base_amount - total_fees.
    pub async fn record_triangular(
        &self,
        exchange_id: u16,
        legs: TriangularLegs,
    ) {
        let id1 = uuid::Uuid::new_v4().to_string();
        let id2 = uuid::Uuid::new_v4().to_string();
        let id3 = uuid::Uuid::new_v4().to_string();
        let now = chrono::Utc::now().timestamp_millis();
        let exchange_name = exchange_name_by_id(exchange_id).to_string();

        // Compute loop P&L.
        // Leg 1: buy base_qty of leg1.quote at leg1.price → cost = leg1.quantity * leg1.price
        //         receive leg1.quantity of leg1.quote
        // Leg 2: buy leg2.quantity of leg2.quote at leg2.price → cost = leg2.quantity * leg2.price
        //         (uses proceeds from leg 1 in terms of leg1.quote)
        // Leg 3: sell leg3.quantity at leg3.price → receive leg3.quantity * leg3.price
        //         (closes the loop back to base currency)
        //
        // For P&L, we compute: final_amount_received - initial_amount_spent - total_fees.
        let initial_cost = legs.leg1_quantity * legs.leg1_price;
        let final_received = legs.leg3_quantity * legs.leg3_price;
        let total_fees = legs.leg1_fee + legs.leg2_fee + legs.leg3_fee;
        let loop_pnl = final_received - initial_cost - total_fees;

        // Split P&L evenly across the three legs for per-leg reporting.
        let _per_leg_pnl = loop_pnl / Decimal::from(3);

        // Clone symbols so we can still reference them in the info! macro
        // after the original values are moved into the TradeRecords.
        let leg1_sym = legs.leg1_symbol.clone();
        let leg2_sym = legs.leg2_symbol.clone();
        let leg3_sym = legs.leg3_symbol.clone();

        // H-4 fix: Record full P&L on the last leg only to avoid triple-counting.
        let record1 = TradeRecord {
            trade_id: id1.clone(),
            timestamp: now,
            exchange_id,
            exchange_name: exchange_name.clone(),
            symbol: legs.leg1_symbol,
            side: "BUY".to_string(),
            quantity: legs.leg1_quantity,
            price: legs.leg1_price,
            fee: legs.leg1_fee,
            pnl_realized: None,
            strategy: "triangular".to_string(),
            pair_trade_id: Some(id2.clone()),
        };

        let record2 = TradeRecord {
            trade_id: id2.clone(),
            timestamp: now,
            exchange_id,
            exchange_name: exchange_name.clone(),
            symbol: legs.leg2_symbol,
            side: if legs.leg2_is_sell { "SELL" } else { "BUY" }.to_string(),
            quantity: legs.leg2_quantity,
            price: legs.leg2_price,
            fee: legs.leg2_fee,
            pnl_realized: None,
            strategy: "triangular".to_string(),
            pair_trade_id: Some(id3.clone()),
        };

        let record3 = TradeRecord {
            trade_id: id3.clone(),
            timestamp: now,
            exchange_id,
            exchange_name: exchange_name.clone(),
            symbol: legs.leg3_symbol,
            side: "SELL".to_string(),
            quantity: legs.leg3_quantity,
            price: legs.leg3_price,
            fee: legs.leg3_fee,
            pnl_realized: Some(loop_pnl),
            strategy: "triangular".to_string(),
            pair_trade_id: Some(id1.clone()),
        };

        {
            let mut records = self.records.lock().unwrap_or_else(|e| e.into_inner());
            for rec in [&record1, &record2, &record3] {
                if let Err(e) = self.append_to_file(rec) {
                    error!(file = %self.file_path, error = %e, "Failed to append triangular leg to JSONL");
                }
                records.push(rec.clone());
            }
        }

        info!(
            exchange = %exchange_name,
            leg1 = %leg1_sym,
            leg2 = %leg2_sym,
            leg3 = %leg3_sym,
            loop_pnl = %loop_pnl,
            "Triangular arb recorded"
        );
    }

    // -----------------------------------------------------------------------
    //  Reporting
    // -----------------------------------------------------------------------

    /// Generate a `PnlReport` from all recorded trades.
    pub async fn generate_report(&self) -> PnlReport {
        let records = self.records.lock().unwrap_or_else(|e| e.into_inner());
        let trades = records.clone();

        let mut total_pnl = Decimal::ZERO;
        let mut total_fees = Decimal::ZERO;
        let mut total_volume = Decimal::ZERO;
        let mut win_count: u64 = 0;
        let mut loss_count: u64 = 0;
        let mut daily_pnl: BTreeMap<String, Decimal> = BTreeMap::new();

        for trade in &trades {
            total_fees += trade.fee;
            total_volume += trade.quantity * trade.price;

            if let Some(pnl) = trade.pnl_realized {
                total_pnl += pnl;
                if pnl > Decimal::ZERO {
                    win_count += 1;
                } else if pnl < Decimal::ZERO {
                    loss_count += 1;
                }
            }

            // Extract the date portion from the unix-millis timestamp.
            let date_key = date_string_from_millis(trade.timestamp);
            *daily_pnl.entry(date_key).or_insert(Decimal::ZERO) +=
                trade.pnl_realized.unwrap_or(Decimal::ZERO);
        }

        PnlReport {
            trades,
            total_pnl,
            total_fees,
            total_volume,
            win_count,
            loss_count,
            daily_pnl,
        }
    }

    /// Load existing trades from the JSONL file on startup.
    pub async fn load_existing(&self) {
        match tokio::fs::read_to_string(&self.file_path).await {
            Ok(contents) => {
                let mut loaded = 0usize;
                let mut parse_errors = 0usize;
                let mut records = self.records.lock().unwrap_or_else(|e| e.into_inner());

                for line in contents.lines() {
                    let line = line.trim();
                    if line.is_empty() {
                        continue;
                    }
                    match serde_json::from_str::<TradeRecord>(line) {
                        Ok(record) => {
                            records.push(record);
                            loaded += 1;
                        }
                        Err(e) => {
                            parse_errors += 1;
                            if parse_errors <= 5 {
                                error!(line_preview = &line[..line.len().min(120)], error = %e,
                                    "Failed to parse trade line from JSONL");
                            }
                        }
                    }
                }

                info!(
                    file = %self.file_path,
                    loaded,
                    parse_errors,
                    "Loaded trade log from JSONL file"
                );
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                info!(file = %self.file_path, "Trade log file does not exist yet, starting fresh");
            }
            Err(e) => {
                error!(file = %self.file_path, error = %e, "Failed to read trade log file");
            }
        }
    }

    /// Print a formatted terminal summary table of P&L stats.
    pub async fn print_summary(&self) {
        let report = self.generate_report().await;

        println!();
        println!("╔══════════════════════════════════════════════════════════════════╗");
        println!("║                    P&L REPORT SUMMARY                           ║");
        println!("╠══════════════════════════════════════════════════════════════════╣");
        println!("║  Total Trades:  {:>10}                                        ║", report.trades.len());
        println!("║  Total Volume:  {:>10} USD                                     ║", report.total_volume.round_dp(2));
        println!("║  Total Fees:    {:>10} USD                                     ║", report.total_fees.round_dp(4));
        println!("╠══════════════════════════════════════════════════════════════════╣");

        let pnl_color = if report.total_pnl >= Decimal::ZERO {
            "+"
        } else {
            ""
        };
        println!("║  NET P&L:       {:>10} USD  ({})                            ║",
            report.total_pnl.round_dp(4), pnl_color);

        let win_rate = if report.win_count + report.loss_count > 0 {
            Decimal::from(report.win_count)
                / Decimal::from(report.win_count + report.loss_count)
                * Decimal::from(100)
        } else {
            Decimal::ZERO
        };
        println!("║  Win Rate:      {:>9.2} %                                        ║", win_rate);
        println!("║  Wins / Losses: {:>4} / {:<4}                                       ║",
            report.win_count, report.loss_count);
        println!("╠══════════════════════════════════════════════════════════════════╣");
        println!("║  DAILY P&L BREAKDOWN                                           ║");
        println!("╠══════════════════════════════════════════════════════════════════╣");

        if report.daily_pnl.is_empty() {
            println!("║  (no trades recorded yet)                                      ║");
        } else {
            for (date, pnl) in &report.daily_pnl {
                let marker = if *pnl >= Decimal::ZERO { "+" } else { "" };
                println!("║  {}  {:>12.4} USD ({})                        ║",
                    date, pnl, marker);
            }
        }

        println!("╚══════════════════════════════════════════════════════════════════╝");
        println!();
    }

    /// Export all trades to a CSV file at the given path.
    pub async fn export_csv(&self, path: &str) {
        let records = self.records.lock().unwrap_or_else(|e| e.into_inner());

        let mut csv_lines: Vec<String> = Vec::with_capacity(records.len() + 1);

        // Header row.
        csv_lines.push(
            "trade_id,timestamp,exchange_id,exchange_name,symbol,side,quantity,price,fee,pnl_realized,strategy,pair_trade_id"
                .to_string(),
        );

        for trade in records.iter() {
            let pnl_str = match trade.pnl_realized {
                Some(p) => p.to_string(),
                None => "".to_string(),
            };
            let pair_str = trade.pair_trade_id.as_deref().unwrap_or("");

            csv_lines.push(format!(
                "{},{},{},\"{}\",\"{}\",\"{}\",{},{},{},{},\"{}\",\"{}\"",
                trade.trade_id,
                trade.timestamp,
                trade.exchange_id,
                trade.exchange_name,
                trade.symbol,
                trade.side,
                trade.quantity,
                trade.price,
                trade.fee,
                pnl_str,
                trade.strategy,
                pair_str,
            ));
        }

        let trade_count = records.len();
        let content = csv_lines.join("\n") + "\n";
        drop(records);

        match tokio::fs::write(path, &content).await {
            Ok(_) => {
                info!(path, trades = trade_count, "Exported trades to CSV");
            }
            Err(e) => {
                error!(path, error = %e, "Failed to write CSV export");
            }
        }
    }

    // -----------------------------------------------------------------------
    //  Internal helpers
    // -----------------------------------------------------------------------

    /// Append a single `TradeRecord` as a JSON line to the log file.
    ///
    /// Uses synchronous file I/O because this is called inside a
    /// `Mutex::lock()` scope and must not hold the lock across an `.await`.
    /// For the expected write volume (a few trades per second at most) this
    /// is perfectly acceptable.
    fn append_to_file(&self, record: &TradeRecord) -> std::io::Result<()> {
        use std::io::Write;

        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .append(true)
            .open(&self.file_path)?;

        let line = serde_json::to_string(record)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        writeln!(file, "{}", line)?;
        Ok(())
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  TriangularLegs — descriptor for a 3-leg triangular arbitrage
// ═══════════════════════════════════════════════════════════════════════════

/// Descriptor for the three legs of a triangular arbitrage cycle.
///
/// Example cycle (USDT base):
/// - Leg 1: BUY BTC with USDT   (BTCUSDT, BUY)
/// - Leg 2: SELL BTC for ETH    (ETHBTC, SELL)
/// - Leg 3: SELL ETH for USDT   (ETHUSDT, SELL)
#[derive(Debug, Clone)]
pub struct TriangularLegs {
    /// First pair symbol (e.g. "BTCUSDT").
    pub leg1_symbol: String,
    /// Quantity traded on leg 1.
    pub leg1_quantity: Decimal,
    /// Execution price on leg 1.
    pub leg1_price: Decimal,
    /// Fee on leg 1.
    pub leg1_fee: Decimal,
    /// Second pair symbol (e.g. "ETHBTC").
    pub leg2_symbol: String,
    /// Quantity traded on leg 2.
    pub leg2_quantity: Decimal,
    /// Execution price on leg 2.
    pub leg2_price: Decimal,
    /// Fee on leg 2.
    pub leg2_fee: Decimal,
    /// Whether leg 2 is a SELL (true) or BUY (false).
    pub leg2_is_sell: bool,
    /// Third pair symbol (e.g. "ETHUSDT").
    pub leg3_symbol: String,
    /// Quantity traded on leg 3.
    pub leg3_quantity: Decimal,
    /// Execution price on leg 3.
    pub leg3_price: Decimal,
    /// Fee on leg 3.
    pub leg3_fee: Decimal,
}

// ═══════════════════════════════════════════════════════════════════════════
//  Periodic P&L printer
// ═══════════════════════════════════════════════════════════════════════════

/// Spawn a background tokio task that prints a P&L summary every 60 seconds.
pub fn start_daily_pnl_printer(trade_log: Arc<TradeLog>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            trade_log.print_summary().await;
        }
    });
}

// ═══════════════════════════════════════════════════════════════════════════
//  Utility
// ═══════════════════════════════════════════════════════════════════════════

/// Convert a unix-millis timestamp to an ISO date string ("2025-01-15").
fn date_string_from_millis(millis: i64) -> String {
    match Utc.timestamp_millis_opt(millis) {
        chrono::LocalResult::Single(dt) => dt.format("%Y-%m-%d").to_string(),
        _ => "1970-01-01".to_string(),
    }
}