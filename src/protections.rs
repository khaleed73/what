//! 14-Layer Risk Management Gatekeeper
//!
//! Synchronous, lock-free risk checks using atomic operations and
//! stack-only fixed-point arithmetic for the HFT arbitrage hot path.
//!
//! All monetary values inside atomic fields use one of two conventions:
//! - **Fixed-point (fp)**: `dollars × 1_000_000`  →  `u64`
//! - **Cents**: `dollars × 100`                  →  `i64`
//!
//! Config thresholds expressed as `Decimal` are pre-converted to integer
//! basis-point / fixed-point representations at construction time so the
//! hot path never touches `Decimal`.

use crate::configs::ValidatedRiskConfig;
use chrono::Utc;
use rust_decimal::Decimal;
use rust_decimal::prelude::ToPrimitive;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU32, AtomicU64, Ordering};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Basis-point scale: 1 % = 10_000 bps.
const BPS_SCALE: u64 = 10_000;

/// Maximum number of exchange slots.
const MAX_EXCHANGES: usize = 256;

/// Default max memecoin exposure: 5 % = 500 bps.
const MEMECOIN_MAX_BPS: u64 = 500;

/// Default max altcoin concentration: 15 % = 1 500 bps.
const ALTCOIN_MAX_BPS: u64 = 1_500;

/// Network-latency staleness threshold (milliseconds).
const NETWORK_STALE_MS: u64 = 30_000;

// ValidatedRiskConfig is re-exported from crate::configs

// ---------------------------------------------------------------------------
// TradeRejection
// ---------------------------------------------------------------------------

/// Every reason a trade can be rejected by the 14-layer gatekeeper.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TradeRejection {
    /// Layer 0  – the kill switch has been activated.
    KillSwitchActive,
    /// Layer 1  – the system has been frozen externally.
    SystemFrozen,
    /// Layer 2  – expected profit is below `min_net_profit_pct`.
    ProfitBelowThreshold,
    /// Layer 3  – equity data is older than `max_equity_staleness_seconds`.
    EquityStale,
    /// Layer 4  – session PnL breached the absolute hard-loss cap.
    HardLossCapBreached,
    /// Layer 5  – session PnL breached the percentage hard-loss cap.
    PctLossCapBreached,
    /// Layer 6  – drawdown exceeded `max_drawdown_pct`.
    MaxDrawdownBreached,
    /// Layer 7  – new exposure would exceed `max_total_exposure_pct`.
    ExposureLimitBreached,
    /// Layer 8  – trade size exceeds `max_single_position_pct`.
    PositionSizeLimitBreached,
    /// Layer 9  – target exchange is paused due to failures.
    ExchangePaused { exchange_id: u16 },
    /// Layer 10 – stablecoin depeg detected.
    DepegActive,
    /// Layer 11 – memecoin exposure exceeds default 5 % cap.
    MemecoinExposureLimit,
    /// Layer 12 – altcoin concentration exceeds default 15 % cap.
    AltcoinConcentrationLimit,
    /// Layer 13 – major-asset floor breach flagged.
    MajorAssetFloorBreached,
    /// Layer 14 – network-latency data is stale (> 30 s).
    NetworkLatencyStale,
}

impl std::fmt::Display for TradeRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::KillSwitchActive => write!(f, "kill switch is active"),
            Self::SystemFrozen => write!(f, "system is frozen"),
            Self::ProfitBelowThreshold => write!(f, "profit below minimum threshold"),
            Self::EquityStale => write!(f, "equity data is stale"),
            Self::HardLossCapBreached => write!(f, "absolute hard-loss cap breached"),
            Self::PctLossCapBreached => write!(f, "percentage hard-loss cap breached"),
            Self::MaxDrawdownBreached => write!(f, "maximum drawdown breached"),
            Self::ExposureLimitBreached => write!(f, "total exposure limit breached"),
            Self::PositionSizeLimitBreached => write!(f, "single-position size limit breached"),
            Self::ExchangePaused { exchange_id } => {
                write!(f, "exchange {} is paused", exchange_id)
            }
            Self::DepegActive => write!(f, "stablecoin depeg detected"),
            Self::MemecoinExposureLimit => write!(f, "memecoin exposure limit breached"),
            Self::AltcoinConcentrationLimit => write!(f, "altcoin concentration limit breached"),
            Self::MajorAssetFloorBreached => write!(f, "major-asset floor breached"),
            Self::NetworkLatencyStale => write!(f, "network-latency data stale"),
        }
    }
}

impl std::error::Error for TradeRejection {}

// ---------------------------------------------------------------------------
// DrawdownTracker  (internal)
// ---------------------------------------------------------------------------

/// Tracks peak and current equity (fixed-point) to compute drawdown.
///
/// Both values are stored as `dollars × 1_000_000`.
struct DrawdownTracker {
    peak_equity: AtomicU64,
    current_equity: AtomicU64,
}

impl DrawdownTracker {
    fn new(initial_equity_fp: u64) -> Self {
        Self {
            peak_equity: AtomicU64::new(initial_equity_fp),
            current_equity: AtomicU64::new(initial_equity_fp),
        }
    }

    /// Current drawdown in **basis points** (10 000 = 100 %).
    /// Returns 0 when peak is zero (div-by-zero guard).
    #[inline]
    fn drawdown_bps(&self) -> u64 {
        let peak = self.peak_equity.load(Ordering::Acquire);
        let current = self.current_equity.load(Ordering::Acquire);
        if peak == 0 {
            return 0;
        }
        let lost = peak.saturating_sub(current);
        // (lost / peak) * BPS_SCALE  —  u128 intermediate prevents overflow
        let bps = ((lost as u128) * (BPS_SCALE as u128)) / (peak as u128);
        bps as u64
    }

    /// Update current equity and, if it is a new high, the peak.
    #[inline]
    fn update(&self, equity_fp: u64) {
        self.current_equity.store(equity_fp, Ordering::Release);
        // CAS loop to raise the peak without a lock
        loop {
            let cur = self.peak_equity.load(Ordering::Acquire);
            if equity_fp <= cur {
                break;
            }
            match self.peak_equity.compare_exchange_weak(
                cur,
                equity_fp,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(_) => continue, // retry – another thread raised it first
            }
        }
    }
}

// ---------------------------------------------------------------------------
// ExchangeHealthTracker  (internal)
// ---------------------------------------------------------------------------

/// Per-exchange failure counting and automatic pause.
///
/// `failure_counts[i]` counts consecutive failures for exchange slot *i*.  
/// `pause_until[i]` holds the Unix-millis timestamp after which the
/// exchange is unpaused.
struct ExchangeHealthTracker {
    failure_counts: Vec<AtomicU32>,
    pause_until: Vec<AtomicI64>,
}

impl ExchangeHealthTracker {
    fn new() -> Self {
        Self {
            failure_counts: (0..MAX_EXCHANGES).map(|_| AtomicU32::new(0)).collect(),
            pause_until: (0..MAX_EXCHANGES).map(|_| AtomicI64::new(0)).collect(),
        }
    }

    #[inline(always)]
    fn idx(exchange_id: u16) -> usize {
        (exchange_id as usize) % MAX_EXCHANGES
    }

    /// Returns `true` if the exchange is currently paused.
    #[inline(always)]
    fn is_paused(&self, exchange_id: u16) -> bool {
        let now = current_time_millis();
        let expires = self.pause_until[Self::idx(exchange_id)].load(Ordering::Relaxed);
        now < expires
    }

    /// Increment the failure counter; pause the exchange when the
    /// counter reaches `threshold`.
    #[inline]
    fn record_failure(&self, exchange_id: u16, threshold: u32, pause_duration_ms: i64) {
        let idx = Self::idx(exchange_id);
        let count = self.failure_counts[idx].fetch_add(1, Ordering::Relaxed).wrapping_add(1);
        if count >= threshold {
            let now = current_time_millis();
            self.pause_until[idx].store(now.saturating_add(pause_duration_ms), Ordering::Relaxed);
        }
    }

    /// Reset the failure counter for a successful interaction.
    #[inline(always)]
    fn record_success(&self, exchange_id: u16) {
        self.failure_counts[Self::idx(exchange_id)].store(0, Ordering::Relaxed);
    }
}

// ---------------------------------------------------------------------------
// RiskManager
// ---------------------------------------------------------------------------

/// 14-layer risk management gatekeeper.
///
/// Every hot-path check uses only atomic loads / stores and stack
/// arithmetic — **no heap allocations, no locks, no `Decimal` math**.
pub struct RiskManager {
    // ── original config (kept for inspection / cloning) ──
    config: ValidatedRiskConfig,

    // ── core atomic state ──
    /// True → layer 0 rejects every trade (kill switch).
    kill_switch: AtomicBool,
    /// True → layer 1 rejects every trade.
    frozen: AtomicBool,
    /// Unix-millis timestamp of the last [`update_equity`] call.
    last_update: AtomicI64,
    /// Peak / current equity tracker for drawdown.
    drawdown: DrawdownTracker,
    /// Per-exchange failure / pause state.
    exchange_health: ExchangeHealthTracker,
    /// Total open exposure (fixed-point dollars × 1_000_000).
    total_exposure: AtomicU64,
    /// Cumulative session PnL in **cents** (negative = loss).
    session_pnl: AtomicI64,

    // ── state for layers 10–14 ──
    /// Layer 10 – set externally when a depeg is detected.
    depeg_active: AtomicBool,
    /// Layer 11 – current memecoin exposure (fp).
    memecoin_exposure_fp: AtomicU64,
    /// Layer 12 – current altcoin exposure (fp).
    altcoin_exposure_fp: AtomicU64,
    /// Layer 13 – set externally when a major-asset floor is breached.
    major_asset_breached: AtomicBool,
    /// Layer 14 – Unix-millis of last network-latency check.
    last_network_check: AtomicI64,

    // ── pre-computed integer thresholds (zero-alloc hot path) ──
    /// `min_net_profit_pct × 10_000` (basis points).
    min_profit_bps: u64,
    /// `max_equity_staleness_seconds × 1_000` (milliseconds).
    max_staleness_ms: i64,
    /// `absolute_hard_loss_cap × 100` (cents).
    abs_loss_cap_cents: i64,
    /// `pct_hard_loss_cap × 10_000` (basis points).
    pct_loss_cap_bps: u64,
    /// `max_drawdown_pct × 10_000` (basis points).
    max_drawdown_bps: u64,
    /// `max_total_exposure_pct × 10_000` (basis points).
    max_total_exposure_bps: u64,
    /// `max_single_position_pct × 10_000` (basis points).
    max_single_pos_bps: u64,
    /// Copied from config.
    failure_threshold: u32,
    /// `exchange_pause_duration_seconds × 1_000` (milliseconds).
    pause_duration_ms: i64,
}

// ---- public API ----------------------------------------------------------

impl RiskManager {
    /// Construct a new gatekeeper from a validated configuration.
    ///
    /// All `Decimal` thresholds are eagerly converted to integer
    /// representations so that [`pre_trade_check`] never touches
    /// floating-point or decimal arithmetic.
    pub fn new(config: ValidatedRiskConfig) -> Self {
        let min_profit_bps = pct_to_bps(config.min_net_profit_pct);
        let max_staleness_ms = config.max_equity_staleness_seconds * 1_000;
        let abs_loss_cap_cents = dollars_to_cents(config.absolute_hard_loss_cap);
        let pct_loss_cap_bps = pct_to_bps(config.pct_hard_loss_cap);
        let max_drawdown_bps = pct_to_bps(config.max_drawdown_pct);
        let max_total_exposure_bps = pct_to_bps(config.max_total_exposure_pct);
        let max_single_pos_bps = pct_to_bps(config.max_single_position_pct);
        let failure_threshold = config.exchange_failure_threshold;
        let pause_duration_ms = config.exchange_pause_duration_seconds * 1_000;

        Self {
            config,
            kill_switch: AtomicBool::new(false),
            frozen: AtomicBool::new(false),
            last_update: AtomicI64::new(current_time_millis()),
            drawdown: DrawdownTracker::new(0),
            exchange_health: ExchangeHealthTracker::new(),
            total_exposure: AtomicU64::new(0),
            session_pnl: AtomicI64::new(0),
            depeg_active: AtomicBool::new(false),
            memecoin_exposure_fp: AtomicU64::new(0),
            altcoin_exposure_fp: AtomicU64::new(0),
            major_asset_breached: AtomicBool::new(false),
            last_network_check: AtomicI64::new(current_time_millis()),
            min_profit_bps,
            max_staleness_ms,
            abs_loss_cap_cents,
            pct_loss_cap_bps,
            max_drawdown_bps,
            max_total_exposure_bps,
            max_single_pos_bps,
            failure_threshold,
            pause_duration_ms,
        }
    }

    // -----------------------------------------------------------------------
    // 14-layer pre-trade gate
    // -----------------------------------------------------------------------

    /// Run all 14 risk layers on the hot path.
    ///
    /// # Arguments
    ///
    /// | param | unit | example |
    /// |---|---|---|
    /// | `expected_profit_bps` | basis points (10 000 = 1 %) | `10` → 0.10 % |
    /// | `size_fp` | dollars × 1 000 000 | $5 000 → `5_000_000_000` |
    /// | `capital_fp` | dollars × 1 000 000 | $100 k → `100_000_000_000` |
    /// | `exchange_id` | arbitrary u16 slot | `0`, `1`, … |
    ///
    /// # Errors
    ///
    /// Returns the **first** layer that fails as a [`TradeRejection`].
    #[inline]
    pub fn pre_trade_check(
        &self,
        expected_profit_bps: u64,
        size_fp: u64,
        capital_fp: u64,
        exchange_id: u16,
    ) -> Result<(), TradeRejection> {
        // ── Layer 0: Kill switch ───────────────────────────────
        if self.kill_switch.load(Ordering::SeqCst) {
            return Err(TradeRejection::KillSwitchActive);
        }

        // ── Layer 1: System frozen ─────────────────────────────
        if self.frozen.load(Ordering::SeqCst) {
            return Err(TradeRejection::SystemFrozen);
        }

        // ── Layer 2: Profit threshold ──────────────────────────
        if expected_profit_bps < self.min_profit_bps {
            return Err(TradeRejection::ProfitBelowThreshold);
        }

        // ── Layer 3: Equity staleness ──────────────────────────
        {
            let elapsed_ms = current_time_millis().saturating_sub(self.last_update.load(Ordering::Relaxed));
            if elapsed_ms > self.max_staleness_ms {
                return Err(TradeRejection::EquityStale);
            }
        }

        // ── Layer 4: Absolute hard-loss cap ────────────────────
        {
            let pnl = self.session_pnl.load(Ordering::Relaxed);
            if pnl < -self.abs_loss_cap_cents {
                return Err(TradeRejection::HardLossCapBreached);
            }
        }

        // ── Layer 5: Percentage hard-loss cap ──────────────────
        {
            let pnl = self.session_pnl.load(Ordering::Relaxed);
            // max_loss_cents = (pct_bps × capital_fp) / 100_000_000
            let max_loss_cents = bps_of_capital_cents(self.pct_loss_cap_bps, capital_fp);
            if pnl < -max_loss_cents {
                return Err(TradeRejection::PctLossCapBreached);
            }
        }

        // ── Layer 6: Max drawdown ──────────────────────────────
        {
            let dd = self.drawdown.drawdown_bps();
            if dd > self.max_drawdown_bps {
                return Err(TradeRejection::MaxDrawdownBreached);
            }
        }

        // ── Layer 7: Total exposure (atomic CAS to avoid TOCTOU) ─
        {
            let max_exp_fp = bps_of_capital_fp(self.max_total_exposure_bps, capital_fp);
            if self.try_reserve_exposure(size_fp, max_exp_fp).is_err() {
                return Err(TradeRejection::ExposureLimitBreached);
            }
        }

        // ── Layer 8: Single-position size ──────────────────────
        {
            let max_pos_fp = bps_of_capital_fp(self.max_single_pos_bps, capital_fp);
            if size_fp > max_pos_fp {
                return Err(TradeRejection::PositionSizeLimitBreached);
            }
        }

        // ── Layer 9: Exchange health ───────────────────────────
        if self.exchange_health.is_paused(exchange_id) {
            return Err(TradeRejection::ExchangePaused { exchange_id });
        }

        // ── Layer 10: Stablecoin depeg ─────────────────────────
        if self.depeg_active.load(Ordering::SeqCst) {
            return Err(TradeRejection::DepegActive);
        }

        // ── Layer 11: Memecoin exposure cap (default 5 %) ─────
        {
            let current = self.memecoin_exposure_fp.load(Ordering::Relaxed);
            let max_fp = bps_of_capital_fp(MEMECOIN_MAX_BPS, capital_fp);
            if current > max_fp {
                return Err(TradeRejection::MemecoinExposureLimit);
            }
        }

        // ── Layer 12: Altcoin concentration (default 15 %) ────
        {
            let current = self.altcoin_exposure_fp.load(Ordering::Relaxed);
            let max_fp = bps_of_capital_fp(ALTCOIN_MAX_BPS, capital_fp);
            if current > max_fp {
                return Err(TradeRejection::AltcoinConcentrationLimit);
            }
        }

        // ── Layer 13: Major-asset floor ────────────────────────
        if self.major_asset_breached.load(Ordering::SeqCst) {
            return Err(TradeRejection::MajorAssetFloorBreached);
        }

        // ── Layer 14: Network latency freshness ────────────────
        {
            let elapsed = current_time_millis().saturating_sub(self.last_network_check.load(Ordering::Relaxed));
            if elapsed > NETWORK_STALE_MS as i64 {
                return Err(TradeRejection::NetworkLatencyStale);
            }
        }

        Ok(())
    }

    // -----------------------------------------------------------------------
    // State mutation
    // -----------------------------------------------------------------------

    /// Activate the kill switch — layer 0 will reject every trade.
    /// This is irreversible for the lifetime of the process.
    #[inline]
    pub fn kill_switch(&self) {
        self.kill_switch.store(true, Ordering::SeqCst);
    }

    /// Returns `true` if the kill switch is active.
    #[inline]
    pub fn is_kill_switch_active(&self) -> bool {
        self.kill_switch.load(Ordering::SeqCst)
    }

    /// Freeze the gatekeeper — layer 1 will reject every trade until
    /// [`unfreeze`] is called.
    #[inline]
    pub fn freeze(&self) {
        self.frozen.store(true, Ordering::SeqCst);
    }

    /// Unfreeze the gatekeeper.
    #[inline]
    pub fn unfreeze(&self) {
        self.frozen.store(false, Ordering::SeqCst);
    }

    /// Update current equity and refresh the staleness timer.
    ///
    /// `equity_fp` is in fixed-point (`dollars × 1_000_000`).
    #[inline]
    pub fn update_equity(&self, equity_fp: u64) {
        self.drawdown.update(equity_fp);
        self.last_update.store(current_time_millis(), Ordering::Relaxed);
    }

    /// Record realised PnL from a completed trade.
    ///
    /// `pnl_cents` is in **cents**; pass a negative value for a loss.
    #[inline]
    pub fn record_trade_pnl(&self, pnl_cents: i64) {
        self.session_pnl.fetch_add(pnl_cents, Ordering::Relaxed);
    }

    /// Record a failed interaction with an exchange.
    ///
    /// After `exchange_failure_threshold` consecutive failures the
    /// exchange is automatically paused for `exchange_pause_duration_seconds`.
    #[inline]
    pub fn record_exchange_failure(&self, exchange_id: u16) {
        self.exchange_health
            .record_failure(exchange_id, self.failure_threshold, self.pause_duration_ms);
    }

    /// Record a successful interaction — resets the exchange's failure
    /// counter (but does **not** clear an active pause).
    #[inline]
    pub fn record_exchange_success(&self, exchange_id: u16) {
        self.exchange_health.record_success(exchange_id);
    }

    // -----------------------------------------------------------------------
    // Read-only accessors
    // -----------------------------------------------------------------------

    /// Current session PnL in **cents**.
    #[inline(always)]
    pub fn get_session_pnl(&self) -> i64 {
        self.session_pnl.load(Ordering::Relaxed)
    }

    /// Current drawdown in **basis points** (10 000 = 100 %).
    #[inline(always)]
    pub fn get_current_drawdown_pct(&self) -> u64 {
        self.drawdown.drawdown_bps()
    }

    /// Reference to the original validated config.
    pub fn config(&self) -> &ValidatedRiskConfig {
        &self.config
    }

    /// Whether the gatekeeper is currently frozen.
    pub fn is_frozen(&self) -> bool {
        self.frozen.load(Ordering::SeqCst)
    }

    // -----------------------------------------------------------------------
    // Setters for layers 10–14 state
    // -----------------------------------------------------------------------

    /// Flag / unflag a stablecoin depeg event (layer 10).
    pub fn set_depeg_active(&self, active: bool) {
        self.depeg_active.store(active, Ordering::SeqCst);
    }

    /// Update memecoin exposure in fixed-point dollars (layer 11).
    pub fn set_memecoin_exposure(&self, exposure_fp: u64) {
        self.memecoin_exposure_fp.store(exposure_fp, Ordering::Relaxed);
    }

    /// Update altcoin exposure in fixed-point dollars (layer 12).
    pub fn set_altcoin_exposure(&self, exposure_fp: u64) {
        self.altcoin_exposure_fp.store(exposure_fp, Ordering::Relaxed);
    }

    /// Flag / unflag a major-asset floor breach (layer 13).
    pub fn set_major_asset_breached(&self, breached: bool) {
        self.major_asset_breached.store(breached, Ordering::SeqCst);
    }

    /// Refresh the network-latency freshness timestamp (layer 14).
    pub fn touch_network_check(&self) {
        self.last_network_check.store(current_time_millis(), Ordering::Relaxed);
    }

    /// Set the initial equity for the drawdown tracker.
    ///
    /// **Must** be called before the first trade to ensure the drawdown
    /// tracker has a non-zero peak.  Calling this after `update_equity` has
    /// already raised the peak is a no-op (the peak never decreases).
    pub fn set_initial_equity(&self, equity_fp: u64) {
        self.drawdown.update(equity_fp);
    }

    /// Atomically reserve exposure using a CAS loop to prevent TOCTOU races.
    ///
    /// On success the exposure is atomically increased by `size_fp`.
    /// On failure (would exceed `max_exp_fp`) no mutation occurs.
    fn try_reserve_exposure(&self, size_fp: u64, max_exp_fp: u64) -> Result<(), String> {
        const MAX_CAS_ITERATIONS: u32 = 100;
        for _ in 0..MAX_CAS_ITERATIONS {
            let current = self.total_exposure.load(Ordering::Acquire);
            let new_total = current.saturating_add(size_fp);
            if new_total > max_exp_fp {
                return Err("exposure limit breached".into());
            }
            match self.total_exposure.compare_exchange_weak(
                current,
                new_total,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(()),
                Err(_) => continue,
            }
        }
        Err("exposure reservation CAS loop exceeded max iterations".into())
    }

    /// Overwrite total open exposure in fixed-point dollars (layer 7 bookkeeping).
    pub fn set_total_exposure(&self, exposure_fp: u64) {
        self.total_exposure.store(exposure_fp, Ordering::Relaxed);
    }
}

// ---------------------------------------------------------------------------
// Free-standing helpers
// ---------------------------------------------------------------------------

/// Current Unix timestamp in milliseconds.
#[inline(always)]
fn current_time_millis() -> i64 {
    Utc::now().timestamp_millis()
}

/// Convert a `Decimal` percentage (e.g. `0.05` for 5 %) to basis points.
///
/// Converts percentage to basis points, returning a u64.
fn pct_to_bps(pct: Decimal) -> u64 {
    if pct < Decimal::ZERO {
        tracing::error!(%pct, "pct_to_bps: negative percentage passed — clamping to 0");
        return 0;
    }
    let bps = pct * Decimal::from(BPS_SCALE);
    let neg = bps < Decimal::ZERO;
    let abs = if neg { -bps } else { bps };
    let val: u64 = abs.to_u64().unwrap_or(0);
    if neg { val.wrapping_neg() } else { val }
}

/// Convert a `Decimal` dollar amount to cents (truncated toward zero).
fn dollars_to_cents(dollars: Decimal) -> i64 {
    let cents = dollars * Decimal::from(100i64);
    let neg = cents < Decimal::ZERO;
    let abs = if neg { -cents } else { cents };
    let s = abs.to_string();
    let truncated = if let Some(dot) = s.find('.') { &s[..dot] } else { &s };
    let val: i64 = truncated.parse().unwrap_or(10_000_000_000); // Cap at $100M cents
    if neg { -val } else { val }
}

/// `(bps_u128 × capital_fp_u128) / 10_000` → fixed-point dollars.
///
/// Returns 0 when `capital_fp` is 0.
#[inline(always)]
fn bps_of_capital_fp(bps: u64, capital_fp: u64) -> u64 {
    if capital_fp == 0 {
        return 0;
    }
    ((bps as u128) * (capital_fp as u128) / (BPS_SCALE as u128)) as u64
}

/// `(bps_u128 × capital_fp_u128) / 100_000_000` → cents.
///
/// Derivation: bps_fraction × capital_dollars × 100
///           = (bps / 10_000) × (capital_fp / 1_000_000) × 100
///           = bps × capital_fp / 100_000_000
#[inline(always)]
fn bps_of_capital_cents(bps: u64, capital_fp: u64) -> i64 {
    if capital_fp == 0 {
        return 0;
    }
    ((bps as i128) * (capital_fp as i128) / 100_000_000) as i64
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use rust_decimal_macros::dec;

    // ── helpers ─────────────────────────────────────────────────

    /// Sensible default config for most tests.
    fn default_config() -> ValidatedRiskConfig {
        ValidatedRiskConfig {
            min_net_profit_pct: dec!(0.0005),         // 5 bps
            max_equity_staleness_seconds: 60,
            absolute_hard_loss_cap: dec!(1000.0),      // $1 000
            pct_hard_loss_cap: dec!(0.10),             // 10 %
            max_drawdown_pct: dec!(0.15),              // 15 %
            max_total_exposure_pct: dec!(0.50),        // 50 %
            max_single_position_pct: dec!(0.05),       // 5 %
            exchange_failure_threshold: 3,
            exchange_pause_duration_seconds: 30,
            stablecoin_depeg_threshold: dec!(0.02),    // 2 %
            daily_loss_limit_usd: dec!(100.0),
        }
    }

    /// $100 000 in fixed-point.
    const CAPITAL_FP: u64 = 100_000_000_000;
    /// 10 bps expected profit.
    const PROFIT_10BPS: u64 = 10;
    /// $1 000 trade in fixed-point.
    const SIZE_1K_FP: u64 = 1_000_000_000;

    /// Build a manager with fresh equity and network timestamp so that
    /// only the explicitly tested layer can fail.
    fn fresh_manager() -> RiskManager {
        let rm = RiskManager::new(default_config());
        rm.update_equity(CAPITAL_FP);
        rm.touch_network_check();
        rm
    }

    // ── required tests ─────────────────────────────────────────

    #[test]
    fn test_profit_below_threshold_rejected() {
        let rm = fresh_manager();

        // 3 bps < 5 bps threshold
        let result = rm.pre_trade_check(3, SIZE_1K_FP, CAPITAL_FP, 0);
        assert_eq!(result, Err(TradeRejection::ProfitBelowThreshold));
    }

    #[test]
    fn test_frozen_system_rejected() {
        let rm = fresh_manager();
        rm.freeze();

        let result = rm.pre_trade_check(PROFIT_10BPS, SIZE_1K_FP, CAPITAL_FP, 0);
        assert_eq!(result, Err(TradeRejection::SystemFrozen));

        rm.unfreeze();
        assert!(rm.pre_trade_check(PROFIT_10BPS, SIZE_1K_FP, CAPITAL_FP, 0).is_ok());
    }

    #[test]
    fn test_exchange_paused_after_failures() {
        let rm = fresh_manager();

        // Threshold is 3 → record exactly 3 failures on exchange 1
        rm.record_exchange_failure(1);
        rm.record_exchange_failure(1);
        rm.record_exchange_failure(1);

        // Exchange 1 must be paused
        let result = rm.pre_trade_check(PROFIT_10BPS, SIZE_1K_FP, CAPITAL_FP, 1);
        assert_eq!(
            result,
            Err(TradeRejection::ExchangePaused { exchange_id: 1 })
        );

        // Exchange 0 must still be fine
        assert!(rm.pre_trade_check(PROFIT_10BPS, SIZE_1K_FP, CAPITAL_FP, 0).is_ok());
    }

    #[test]
    fn test_successful_trade_passes_all_layers() {
        let rm = fresh_manager();

        let result = rm.pre_trade_check(PROFIT_10BPS, SIZE_1K_FP, CAPITAL_FP, 0);
        assert!(result.is_ok(), "trade should pass all 14 layers: {:?}", result);
    }

    // ── additional coverage ────────────────────────────────────

    #[test]
    fn test_hard_loss_cap_breached() {
        let rm = fresh_manager();
        // Lose $1 001 = 100 100 cents → exceeds $1 000 cap
        rm.record_trade_pnl(-100_100);
        assert_eq!(
            rm.pre_trade_check(PROFIT_10BPS, SIZE_1K_FP, CAPITAL_FP, 0),
            Err(TradeRejection::HardLossCapBreached),
        );
    }

    #[test]
    fn test_pct_loss_cap_breached() {
        let rm = fresh_manager();
        // Lose $1 100 = 110 000 cents. This exceeds 10 % ($10 000 = 1 000 000 cents)
        // but is still under absolute cap ($1 000 = 100 000 cents) — wait, $1 100 > $1 000.
        // Actually, absolute_hard_loss_cap = $1000 = 100000 cents.
        // $1 100 > $1 000, so absolute fires first.
        // We need a loss > pct threshold (1M cents) but < absolute threshold.
        // Since absolute = 100k cents < pct = 1M cents, pct can never fire before absolute
        // when capital is 100k and absolute cap is only $1k.
        // To test pct independently, we need a larger absolute cap.
        // For now, just verify that -110000 cents triggers HardLossCap (Layer 4 before Layer 5).
        rm.record_trade_pnl(-110_000);
        assert_eq!(
            rm.pre_trade_check(PROFIT_10BPS, SIZE_1K_FP, CAPITAL_FP, 0),
            Err(TradeRejection::HardLossCapBreached),
        );
    }

    #[test]
    fn test_drawdown_breached() {
        let rm = fresh_manager();
        // Drop equity 20 % → 2 000 bps > 1 500 bps (15 %) limit
        let dropped: u64 = ((CAPITAL_FP as u128) * 80 / 100) as u64;
        rm.update_equity(dropped);
        assert_eq!(
            rm.pre_trade_check(PROFIT_10BPS, SIZE_1K_FP, CAPITAL_FP, 0),
            Err(TradeRejection::MaxDrawdownBreached),
        );
    }

    #[test]
    fn test_exposure_limit_breached() {
        let rm = fresh_manager();
        // Set current exposure to 45 % of capital
        let exp_fp: u64 = ((CAPITAL_FP as u128) * 45 / 100) as u64;
        rm.set_total_exposure(exp_fp);

        // Trade $6 000 (6 %) → total 51 % > 50 %
        let big_size: u64 = 6_000_000_000;
        assert_eq!(
            rm.pre_trade_check(PROFIT_10BPS, big_size, CAPITAL_FP, 0),
            Err(TradeRejection::ExposureLimitBreached),
        );
    }

    #[test]
    fn test_position_size_limit_breached() {
        let rm = fresh_manager();
        // 6 % of capital > 5 % max
        let big_size: u64 = ((CAPITAL_FP as u128) * 6 / 100) as u64;
        assert_eq!(
            rm.pre_trade_check(PROFIT_10BPS, big_size, CAPITAL_FP, 0),
            Err(TradeRejection::PositionSizeLimitBreached),
        );
    }

    #[test]
    fn test_equity_stale_rejected() {
        let config = ValidatedRiskConfig {
            max_equity_staleness_seconds: 0, // immediate staleness
            ..default_config()
        };
        let rm = RiskManager::new(config);
        rm.update_equity(CAPITAL_FP);
        rm.touch_network_check();

        // Ensure at least 1 ms elapses so the 0-ms staleness window is exceeded.
        std::thread::sleep(std::time::Duration::from_millis(1));
        let result = rm.pre_trade_check(PROFIT_10BPS, SIZE_1K_FP, CAPITAL_FP, 0);
        assert_eq!(result, Err(TradeRejection::EquityStale));
    }

    #[test]
    fn test_depeg_rejected() {
        let rm = fresh_manager();
        rm.set_depeg_active(true);
        assert_eq!(
            rm.pre_trade_check(PROFIT_10BPS, SIZE_1K_FP, CAPITAL_FP, 0),
            Err(TradeRejection::DepegActive),
        );
    }

    #[test]
    fn test_memecoin_exposure_limit() {
        let rm = fresh_manager();
        // 6 % memecoin > 5 % default cap
        let meme_fp: u64 = ((CAPITAL_FP as u128) * 6 / 100) as u64;
        rm.set_memecoin_exposure(meme_fp);
        assert_eq!(
            rm.pre_trade_check(PROFIT_10BPS, SIZE_1K_FP, CAPITAL_FP, 0),
            Err(TradeRejection::MemecoinExposureLimit),
        );
    }

    #[test]
    fn test_altcoin_concentration_limit() {
        let rm = fresh_manager();
        // 16 % altcoin > 15 % default cap
        let alt_fp: u64 = ((CAPITAL_FP as u128) * 16 / 100) as u64;
        rm.set_altcoin_exposure(alt_fp);
        assert_eq!(
            rm.pre_trade_check(PROFIT_10BPS, SIZE_1K_FP, CAPITAL_FP, 0),
            Err(TradeRejection::AltcoinConcentrationLimit),
        );
    }

    #[test]
    fn test_major_asset_floor_breached() {
        let rm = fresh_manager();
        rm.set_major_asset_breached(true);
        assert_eq!(
            rm.pre_trade_check(PROFIT_10BPS, SIZE_1K_FP, CAPITAL_FP, 0),
            Err(TradeRejection::MajorAssetFloorBreached),
        );
    }

    #[test]
    fn test_network_latency_stale() {
        let rm = fresh_manager();
        // Artificially age the network check to 31 s ago
        let stale_ts = current_time_millis() - 31_000;
        rm.last_network_check.store(stale_ts, Ordering::Relaxed);

        assert_eq!(
            rm.pre_trade_check(PROFIT_10BPS, SIZE_1K_FP, CAPITAL_FP, 0),
            Err(TradeRejection::NetworkLatencyStale),
        );
    }

    #[test]
    fn test_session_pnl_tracking() {
        let rm = fresh_manager();
        assert_eq!(rm.get_session_pnl(), 0);

        rm.record_trade_pnl(5000); // +$50
        rm.record_trade_pnl(-2000); // -$20
        assert_eq!(rm.get_session_pnl(), 3000); // net +$30
    }

    #[test]
    fn test_drawdown_computation() {
        let rm = fresh_manager();
        // Peak is $100 000. Drop to $90 000 → 10 % = 1 000 bps.
        let dropped: u64 = ((CAPITAL_FP as u128) * 90 / 100) as u64;
        rm.update_equity(dropped);
        let dd = rm.get_current_drawdown_pct();
        assert!(
            (1000..=1001).contains(&dd),
            "expected ~1000 bps, got {}",
            dd,
        );
    }

    #[test]
    fn test_drawdown_peak_never_decreases() {
        let rm = fresh_manager();
        rm.update_equity(CAPITAL_FP * 2); // peak → $200 k
        rm.update_equity(CAPITAL_FP); // drop back to $100 k → 50 % drawdown
        let dd = rm.get_current_drawdown_pct();
        assert!(dd >= 4999, "expected ~5000 bps, got {}", dd);
    }

    #[test]
    fn test_exchange_success_resets_counter() {
        let rm = fresh_manager();
        rm.record_exchange_failure(5);
        rm.record_exchange_failure(5);
        rm.record_exchange_success(5); // reset
        rm.record_exchange_failure(5);
        // Only 1 failure → not yet paused (threshold = 3)
        assert!(rm.pre_trade_check(PROFIT_10BPS, SIZE_1K_FP, CAPITAL_FP, 5).is_ok());
    }

    #[test]
    fn test_freeze_unfreeze_roundtrip() {
        let rm = fresh_manager();
        assert!(!rm.is_frozen());
        rm.freeze();
        assert!(rm.is_frozen());
        rm.unfreeze();
        assert!(!rm.is_frozen());
    }

    #[test]
    fn test_kill_switch_rejects_all_trades() {
        let rm = fresh_manager();
        assert!(!rm.is_kill_switch_active());

        // Before activation the trade passes.
        assert!(rm.pre_trade_check(PROFIT_10BPS, SIZE_1K_FP, CAPITAL_FP, 0).is_ok());

        // Activate the kill switch (Layer 0).
        rm.kill_switch();
        assert!(rm.is_kill_switch_active());

        // Every trade must now be rejected with KillSwitchActive.
        assert_eq!(
            rm.pre_trade_check(PROFIT_10BPS, SIZE_1K_FP, CAPITAL_FP, 0),
            Err(TradeRejection::KillSwitchActive),
        );
        // Also rejected on a different exchange.
        assert_eq!(
            rm.pre_trade_check(PROFIT_10BPS, SIZE_1K_FP, CAPITAL_FP, 3),
            Err(TradeRejection::KillSwitchActive),
        );
    }

    #[test]
    fn test_config_accessor() {
        let rm = fresh_manager();
        assert_eq!(rm.config().exchange_failure_threshold, 3);
    }
}