// configs.rs — TOML configuration parser & validator for the HFT arbitrage bot.
//
// All floating-point numeric fields that arrive as TOML strings are converted to
// `rust_decimal::Decimal` at boot time so that every downstream calculation
// operates with exact fixed-point arithmetic.

use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::str::FromStr;

use rust_decimal::prelude::FromPrimitive;
use rust_decimal::Decimal;
use serde::Deserialize;

/// Maximum number of exchanges supported by the u64 bitmask system.
const MAX_EXCHANGES: usize = 64;
/// Minimum length for a valid blockchain deposit address (after "0x" prefix).
const MIN_DEPOSIT_ADDR_LEN: usize = 10;
/// Maximum length for a blockchain deposit address.
const MAX_DEPOSIT_ADDR_LEN: usize = 44;

// ═══════════════════════════════════════════════════════════════════════════
//  Raw (TOML-mirroring) structs — parsed directly via serde::Deserialize
// ═══════════════════════════════════════════════════════════════════════════

/// Top-level config as it appears on disk.
#[derive(Debug, Deserialize)]
pub struct RawConfig {
    /// When true, overrides auto-detection and forces LIVE trading mode.
    /// When false (default), auto-detects paper mode from placeholder keys.
    #[serde(default)]
    pub force_live_mode: bool,
    pub vps_settings: VpsSettings,
    pub discord: DiscordConfig,
    pub strategies: RawStrategies,
    pub exchanges: HashMap<String, RawExchangeConfig>,
    pub risk_limits: RawRiskLimits,
    /// Entire `[stablecoin]` section is optional; defaults are used when absent.
    #[serde(default)]
    pub stablecoin: StablecoinConfig,
    /// Entire `[friction_protections]` section is optional; defaults are used when absent.
    #[serde(default)]
    pub friction_protections: RawFrictionProtections,
    /// Deposit addresses per exchange/network, keyed as "ExchangeName_network".
    #[serde(default)]
    pub deposit_addresses: HashMap<String, String>,
}

// ── Leaf sections ────────────────────────────────────────────────────────

/// VPS deployment settings (CPU pinning, network tuning).
#[derive(Debug, Deserialize, Clone)]
pub struct VpsSettings {
    /// CPU core index to pin the trading thread to (0-based).
    pub pinned_cpu_core: usize,
    /// Network interface listen backlog (e.g. `somaxconn`).
    pub network_interface_backlog: u32,
}

/// Discord webhook notification settings.
#[derive(Debug, Deserialize, Clone)]
pub struct DiscordConfig {
    /// Discord webhook URL for trade alerts.
    pub webhook_url: String,
    /// Maximum number of notifications buffered before flushing.
    pub buffer_capacity: usize,
}

// ── Strategies ───────────────────────────────────────────────────────────

/// Raw strategy configuration as parsed from TOML.
#[derive(Debug, Deserialize)]
pub struct RawStrategies {
    /// Cross-exchange arbitrage strategy settings.
    pub cross_exchange: RawCrossExchangeConfig,
    /// Triangular arbitrage strategy settings.
    pub triangular: RawTriangularConfig,
}

/// Raw cross-exchange strategy config (numeric fields as strings).
#[derive(Debug, Deserialize)]
pub struct RawCrossExchangeConfig {
    /// Whether this strategy is active.
    pub enabled: bool,
    /// Minimum spread percentage (as a decimal string, e.g. "0.001").
    pub min_spread_pct: String,
    /// Maximum allowed round-trip latency in milliseconds.
    pub max_target_latency_ms: u64,
    /// Minimum L2 order book liquidity in USD required for signal emission.
    pub min_l2_liquidity_usd: String,
    /// Maximum slippage tolerance as a fraction (e.g. "0.0005").
    pub max_slippage_tolerance: String,
    /// Optional allowlist of exchange IDs for this strategy.
    /// When present, only signals involving these exchanges are emitted.
    /// When absent/empty, ALL configured exchanges are eligible (default).
    #[serde(default)]
    pub exchanges: Option<Vec<u16>>,
}

/// Raw triangular arbitrage config (numeric fields as strings).
#[derive(Debug, Deserialize)]
pub struct RawTriangularConfig {
    /// Whether this strategy is active.
    pub enabled: bool,
    /// Minimum loop profit percentage (decimal string).
    pub min_loop_profit_pct: String,
    /// Maximum path length in hops (must be >= 3).
    pub max_path_length: u32,
    /// Minimum 24h trading volume for a pair (decimal string, USD).
    pub min_pair_volume_24h: String,
    /// Quote currency anchors for loop discovery (e.g. ["USDT", "USDC"]).
    pub quote_anchors: Vec<String>,
    /// Optional allowlist of exchange IDs for this strategy.
    /// When present, only signals on these exchanges are emitted.
    /// When absent/empty, ALL configured exchanges are eligible (default).
    #[serde(default)]
    pub exchanges: Option<Vec<u16>>,
}

// ── Exchanges (dynamic `[exchanges.<name>]`) ────────────────────────────

/// Raw per-exchange configuration as parsed from TOML.
#[derive(Debug, Deserialize, Clone)]
pub struct RawExchangeConfig {
    /// Numeric exchange identifier (used as HashMap key in validated config).
    pub id: u16,
    /// Exchange name (must match the TOML section key).
    pub name: String,
    /// API key for authenticated endpoints.
    /// TODO: Use zeroizing SecretString for api_key and api_secret
    /// (see `exchange::config::SecretString` for the secure wrapper already used downstream).
    pub api_key: String,
    /// API secret for request signing.
    /// TODO: Use zeroizing SecretString for api_key and api_secret
    /// (see `exchange::config::SecretString` for the secure wrapper already used downstream).
    pub api_secret: String,
    /// Optional passphrase (required by OKX, KuCoin, Bitget).
    #[serde(default)]
    pub passphrase: Option<String>,
    /// WebSocket URL for real-time market data.
    pub wss_url: String,
    /// REST API base URL.
    pub rest_url: String,
}

// ── Risk limits ──────────────────────────────────────────────────────────

/// Raw risk limits configuration (numeric fields as strings).
#[derive(Debug, Deserialize)]
pub struct RawRiskLimits {
    /// Minimum net profit percentage required to execute a trade.
    pub min_net_profit_pct: String,
    /// Maximum seconds without an equity update before halting.
    pub max_equity_staleness_seconds: i64,
    /// Absolute hard loss cap in USD.
    pub absolute_hard_loss_cap: String,
    /// Percentage hard loss cap (fraction, e.g. "0.02" = 2%).
    pub pct_hard_loss_cap: String,
    /// Maximum drawdown percentage before halting.
    pub max_drawdown_pct: String,
    /// Maximum total exposure as a fraction of equity.
    pub max_total_exposure_pct: String,
    /// Maximum single-position size as a fraction of equity.
    pub max_single_position_pct: String,
    /// Consecutive failures before pausing an exchange.
    pub exchange_failure_threshold: u32,
    /// Seconds to pause an exchange after reaching the failure threshold.
    pub exchange_pause_duration_seconds: i64,
    /// Stablecoin depeg threshold (decimal string).
    #[serde(default = "default_stablecoin_depeg_threshold")]
    pub stablecoin_depeg_threshold: String,
    /// Maximum daily loss in USD (as a string decimal, e.g. "100.00").
    /// The execution engine halts trading for the rest of the UTC day once
    /// cumulative realised losses reach this amount.  Default: 100.00 ($100).
    #[serde(default = "default_daily_loss_limit")]
    pub daily_loss_limit_usd: String,
}

// ── Stablecoin depeg monitoring ─────────────────────────────────────────

/// Raw stablecoin config with `f64` fields.
///
/// Stored as f64 for TOML deserialization convenience.
/// Converted to Decimal during validation (see validate_stablecoin).
/// NOTE: f64 precision loss (~15 digits) is acceptable for threshold
/// percentages (e.g., 0.005 = 0.5% depeg threshold).
#[derive(Debug, Deserialize, Clone)]
pub struct StablecoinConfig {
    pub depeg_threshold: f64,
    pub usdt_max_pct: f64,
    pub usdc_min_pct: f64,
    #[serde(default)]
    pub monitored_symbols: Vec<String>,
}

// ── Friction protections (trading fees, transfer gas) ──────────────────

/// Raw friction protections config mirroring the `[friction_protections]` TOML section.
/// All fields are optional with sensible defaults.
#[derive(Debug, Deserialize, Clone)]
pub struct RawFrictionProtections {
    /// Gas/network fee in USD deducted from each inter-exchange transfer.
    /// Prevents the balance matrix from over-crediting the destination exchange.
    #[serde(default = "default_gas_fee")]
    pub transfer_gas_fee_usd: String,
    /// Fee-aware mode toggle. When `true` (default), trading fees are deducted
    /// from raw spreads before signal emission.
    #[serde(default = "default_true")]
    pub fee_aware_enabled: bool,
    /// Default taker fee as a fraction string (e.g. "0.0010" = 10 bps).
    /// Used when per-exchange overrides are not specified.
    #[serde(default = "default_taker_fee")]
    pub default_taker_fee_pct: String,
    /// Per-exchange taker fee overrides in basis points.
    /// Keys are exchange names as they appear in `[exchanges.<name>]`.
    #[serde(default)]
    pub exchange_taker_fees: HashMap<String, u64>,
}

/// Default gas/network fee in USD for inter-exchange transfers.
fn default_gas_fee() -> String { "2.00".to_string() }
/// Default value for boolean fields that default to true.
fn default_true() -> bool { true }
/// Default taker fee as a fraction (10 bps = 0.001).
fn default_taker_fee() -> String { "0.0010".to_string() }
/// Default daily loss limit in USD.
fn default_daily_loss_limit() -> String { "100.00".to_string() }
fn default_stablecoin_depeg_threshold() -> String { "0.02".to_string() }

impl Default for RawFrictionProtections {
    /// Returns defaults: $2.00 gas fee, fee-aware enabled, 10 bps taker fee.
    fn default() -> Self {
        Self {
            transfer_gas_fee_usd: default_gas_fee(),
            fee_aware_enabled: true,
            default_taker_fee_pct: default_taker_fee(),
            exchange_taker_fees: HashMap::new(),
        }
    }
}

impl Default for StablecoinConfig {
    /// Sensible defaults consumed by the depeg module when `[stablecoin]`
    /// is omitted from `config.toml`.
    fn default() -> Self {
        // Default depeg threshold: 0.998 (0.2% depeg)
        // Default USDT max allocation: 80%
        // Default USDC min allocation: 20%
        Self {
            depeg_threshold: 0.998,
            usdt_max_pct: 0.80,
            usdc_min_pct: 0.20,
            monitored_symbols: Vec::new(),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  Validated structs — every numeric String is now a `Decimal`
// ═══════════════════════════════════════════════════════════════════════════

/// Fully validated risk configuration.
///
/// Kept `pub` so that other modules (e.g. `crate::protections`) can re-export
/// or reference it directly.
#[derive(Debug, Clone)]
pub struct ValidatedRiskConfig {
    /// Minimum net profit percentage required to execute a trade.
    pub min_net_profit_pct: Decimal,
    /// Maximum seconds without an equity update before halting.
    pub max_equity_staleness_seconds: i64,
    /// Absolute hard loss cap in USD.
    pub absolute_hard_loss_cap: Decimal,
    /// Percentage hard loss cap (fraction).
    pub pct_hard_loss_cap: Decimal,
    /// Maximum drawdown percentage before halting.
    pub max_drawdown_pct: Decimal,
    /// Maximum total exposure as a fraction of equity.
    pub max_total_exposure_pct: Decimal,
    /// Maximum single-position size as a fraction of equity.
    pub max_single_position_pct: Decimal,
    /// Consecutive failures before pausing an exchange.
    pub exchange_failure_threshold: u32,
    /// Seconds to pause an exchange after reaching the failure threshold.
    pub exchange_pause_duration_seconds: i64,
    /// Stablecoin depeg threshold.
    pub stablecoin_depeg_threshold: Decimal,
    /// Maximum daily loss in USD.  The execution engine converts this to
    /// cents at boot and halts trading once the daily loss counter reaches
    /// this threshold.
    pub daily_loss_limit_usd: Decimal,
}

#[derive(Debug, Clone)]
pub struct ValidatedCrossExchangeConfig {
    pub enabled: bool,
    pub min_spread_pct: Decimal,
    pub max_target_latency_ms: u64,
    /// Reserved for future L2 liquidity gate on signal emission.
    pub min_l2_liquidity_usd: Decimal,
    pub max_slippage_tolerance: Decimal,
    /// Optional allowlist of exchange IDs. None = all exchanges eligible.
    pub exchanges: Option<Vec<u16>>,
}

#[derive(Debug, Clone)]
pub struct ValidatedTriangularConfig {
    pub enabled: bool,
    pub min_loop_profit_pct: Decimal,
    /// Reserved: only 3-hop loops are currently supported.
    pub max_path_length: u32,
    /// Reserved for future volume filtering on loop discovery.
    pub min_pair_volume_24h: Decimal,
    pub quote_anchors: Vec<String>,
    /// Optional allowlist of exchange IDs. None = all exchanges eligible.
    pub exchanges: Option<Vec<u16>>,
}

#[derive(Clone)]
pub struct ValidatedExchangeConfig {
    pub id: u16,
    pub name: String,
    /// TODO: Use zeroizing SecretString (see `exchange::config::SecretString`).
    pub api_key: String,
    /// TODO: Use zeroizing SecretString (see `exchange::config::SecretString`).
    pub api_secret: String,
    pub passphrase: Option<String>,
    pub wss_url: String,
    pub rest_url: String,
}

impl std::fmt::Debug for ValidatedExchangeConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ValidatedExchangeConfig")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("api_key", &"[REDACTED]")
            .field("api_secret", &"[REDACTED]")
            .field("passphrase", &self.passphrase.as_ref().map(|_| "[REDACTED]"))
            .field("wss_url", &self.wss_url)
            .field("rest_url", &self.rest_url)
            .finish()
    }
}

#[derive(Debug, Clone)]
pub struct ValidatedStablecoinConfig {
    pub depeg_threshold: Decimal,
    pub usdt_max_pct: Decimal,
    pub usdc_min_pct: Decimal,
    pub monitored_symbols: Vec<String>,
}

/// Validated friction protections configuration.
///
/// Consumed by `main.rs` to configure the rebalancer gas fee, the strategy
/// engine's fee schedule, and the execution engine's slippage tolerance.
#[derive(Debug, Clone)]
pub struct ValidatedFrictionProtections {
    /// Gas/network fee per inter-exchange transfer, in USD.
    pub transfer_gas_fee_usd: Decimal,
    /// When `true`, the strategy engine deducts round-trip trading fees
    /// from raw spreads before emitting signals.
    pub fee_aware_enabled: bool,
    /// Default taker fee as a fraction (e.g. 0.001 = 10 bps).
    pub default_taker_fee_pct: Decimal,
    /// Per-exchange taker fee overrides in basis points.
    /// Keyed by exchange name (e.g. "Binance" → 10).
    pub exchange_taker_fees: HashMap<String, u64>,
}

#[derive(Debug, Clone)]
pub struct ValidatedStrategies {
    pub cross_exchange: ValidatedCrossExchangeConfig,
    pub triangular: ValidatedTriangularConfig,
}

// ═══════════════════════════════════════════════════════════════════════════
//  EngineConfig — the single entry-point consumed by the rest of the crate
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone)]
pub struct EngineConfig {
    /// When true, forces live mode even if some keys look like placeholders.
    pub force_live_mode: bool,
    pub vps: VpsSettings,
    pub discord: DiscordConfig,
    pub strategies: ValidatedStrategies,
    pub risk: ValidatedRiskConfig,
    /// Exchanges keyed by their numeric `id` for O(1) lookup.
    pub exchanges: HashMap<u16, ValidatedExchangeConfig>,
    pub stablecoin: ValidatedStablecoinConfig,
    /// Friction protections: gas fees, trading fee schedule, slippage.
    pub friction_protections: ValidatedFrictionProtections,
    /// Deposit addresses keyed as "ExchangeName_network" → address string.
    pub deposit_addresses: HashMap<String, String>,
}

// ── Validation helpers ───────────────────────────────────────────────────

/// Parse a `&str` into a `Decimal`, annotating the field name on failure.
#[inline]
fn parse_decimal(s: &str, field: &str) -> Result<Decimal, Box<dyn std::error::Error>> {
    Decimal::from_str(s).map_err(|e| {
        format!(
            "Failed to parse '{}' as Decimal for field '{}': {}",
            s, field, e
        )
        .into()
    })
}

/// Assert that a percentage value lies in [0, 1].
#[inline]
fn validate_pct_range(value: Decimal, field: &str) -> Result<(), Box<dyn std::error::Error>> {
    if value < Decimal::ZERO || value > Decimal::ONE {
        return Err(format!(
            "Field '{}' = {} must be between 0 and 1 (inclusive)",
            field, value
        )
        .into());
    }
    Ok(())
}

/// Assert that a value is strictly positive (> 0).
#[inline]
fn validate_positive(value: Decimal, field: &str) -> Result<(), Box<dyn std::error::Error>> {
    if value <= Decimal::ZERO {
        return Err(format!(
            "Field '{}' = {} must be strictly greater than 0",
            field, value
        )
        .into());
    }
    Ok(())
}

/// Convert an `f64` to `Decimal`, preserving the float's bit representation.
#[inline]
fn f64_to_decimal(val: f64, field: &str) -> Result<Decimal, Box<dyn std::error::Error>> {
    Decimal::from_f64(val).ok_or_else(|| {
        format!(
            "Failed to convert f64 value {} for field '{}' to Decimal",
            val, field
        )
        .into()
    })
}


/// Assert that a percentage value is strictly positive (> 0, <= 1).
/// Used for profit minimums and loss caps where 0 would be financially dangerous.
#[inline]
fn validate_strictly_positive_pct(value: Decimal, field: &str) -> Result<(), Box<dyn std::error::Error>> {
    if value <= Decimal::ZERO || value > Decimal::ONE {
        return Err(format!(
            "Field '{}' = {} must be strictly between 0 and 1 (exclusive of 0)",
            field, value
        )
        .into());
    }
    Ok(())
}
/// Validate that an `i64` is strictly positive (> 0).
#[inline]
fn validate_positive_i64(value: i64, field: &str) -> Result<(), Box<dyn std::error::Error>> {
    if value <= 0 {
        return Err(format!(
            "Field '{}' = {} must be strictly greater than 0",
            field, value
        )
        .into());
    }
    Ok(())
}

// ── Environment variable helpers ────────────────────────────────────────

/// Check an environment variable and return `Some(value)` if it is set and
/// non-empty.  Returns `None` when the variable is absent or blank, so
/// callers can use `.unwrap_or(config_value)` to fall back to TOML.
#[inline]
fn env_override(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|v| !v.is_empty())
}

/// Convert an exchange name (e.g. "KuCoin", "GateIO") into the uppercase
/// env-var prefix used for secret overrides (e.g. "KUCOIN", "GATEIO").
#[inline]
fn exchange_env_prefix(name: &str) -> String {
    name.chars()
        .filter(|c| c.is_alphanumeric())
        .flat_map(|c| c.to_uppercase())
        .collect()
}

// ── EngineConfig implementation ──────────────────────────────────────────

impl EngineConfig {
    /// Read the TOML file at `path`, deserialize it, convert every numeric
    /// string to `Decimal`, and validate all ranges.
    ///
    /// This is the single boot-time entry point; any failure short-circuits
    /// with a descriptive error.
    pub fn load_and_validate<P: AsRef<Path>>(
        path: P,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        // Load .env file (if present) so secrets can be supplied outside
        // of the TOML config.  Silently ignore if the file is missing.
        dotenvy::dotenv().ok();

        let contents = fs::read_to_string(&path)
            .map_err(|e| format!("failed to read config file '{}': {}", path.as_ref().display(), e))?;
        let raw: RawConfig = toml::from_str(&contents)
            .map_err(|e| format!("failed to parse TOML from '{}': {}", path.as_ref().display(), e))?;

        // ── Strategies ───────────────────────────────────────────────────

        let cross_exchange = {
            let r = &raw.strategies.cross_exchange;
            let min_spread_pct = parse_decimal(&r.min_spread_pct,
                "strategies.cross_exchange.min_spread_pct")?;
            validate_strictly_positive_pct(min_spread_pct, "strategies.cross_exchange.min_spread_pct")?;

            let min_l2_liquidity_usd = parse_decimal(&r.min_l2_liquidity_usd,
                "strategies.cross_exchange.min_l2_liquidity_usd")?;
            validate_positive(min_l2_liquidity_usd,
                "strategies.cross_exchange.min_l2_liquidity_usd")?;

            let max_slippage_tolerance = parse_decimal(&r.max_slippage_tolerance,
                "strategies.cross_exchange.max_slippage_tolerance")?;
            validate_pct_range(max_slippage_tolerance,
                "strategies.cross_exchange.max_slippage_tolerance")?;

            ValidatedCrossExchangeConfig {
                enabled: r.enabled,
                min_spread_pct,
                max_target_latency_ms: r.max_target_latency_ms,
                min_l2_liquidity_usd,
                max_slippage_tolerance,
                // Normalise None/empty → None (all exchanges eligible).
                exchanges: r.exchanges.as_ref().filter(|v| !v.is_empty()).cloned(),
            }
        };

        let triangular = {
            let r = &raw.strategies.triangular;
            let min_loop_profit_pct = parse_decimal(&r.min_loop_profit_pct,
                "strategies.triangular.min_loop_profit_pct")?;
            validate_pct_range(min_loop_profit_pct,
                "strategies.triangular.min_loop_profit_pct")?;

            let min_pair_volume_24h = parse_decimal(&r.min_pair_volume_24h,
                "strategies.triangular.min_pair_volume_24h")?;
            validate_positive(min_pair_volume_24h,
                "strategies.triangular.min_pair_volume_24h")?;

            if r.max_path_length < 3 {
                return Err(format!(
                    "strategies.triangular.max_path_length = {} must be >= 3",
                    r.max_path_length
                )
                .into());
            }

            if r.quote_anchors.is_empty() {
                return Err(
                    "strategies.triangular.quote_anchors must contain at least one entry"
                        .into(),
                );
            }

            ValidatedTriangularConfig {
                enabled: r.enabled,
                min_loop_profit_pct,
                max_path_length: r.max_path_length,
                min_pair_volume_24h,
                quote_anchors: r.quote_anchors.clone(),
                // Normalise None/empty → None (all exchanges eligible).
                exchanges: r.exchanges.as_ref().filter(|v| !v.is_empty()).cloned(),
            }
        };

        // ── Risk limits ──────────────────────────────────────────────────

        let risk = {
            let r = &raw.risk_limits;

            let min_net_profit_pct = parse_decimal(&r.min_net_profit_pct,
                "risk_limits.min_net_profit_pct")?;
            validate_strictly_positive_pct(min_net_profit_pct, "risk_limits.min_net_profit_pct")?;

            validate_positive_i64(r.max_equity_staleness_seconds,
                "risk_limits.max_equity_staleness_seconds")?;

            let absolute_hard_loss_cap = parse_decimal(&r.absolute_hard_loss_cap,
                "risk_limits.absolute_hard_loss_cap")?;
            validate_positive(absolute_hard_loss_cap,
                "risk_limits.absolute_hard_loss_cap")?;

            let pct_hard_loss_cap = parse_decimal(&r.pct_hard_loss_cap,
                "risk_limits.pct_hard_loss_cap")?;
            validate_strictly_positive_pct(pct_hard_loss_cap, "risk_limits.pct_hard_loss_cap")?;

            let max_drawdown_pct = parse_decimal(&r.max_drawdown_pct,
                "risk_limits.max_drawdown_pct")?;
            validate_strictly_positive_pct(max_drawdown_pct, "risk_limits.max_drawdown_pct")?;
            // M-7: A 100% drawdown (losing everything) must be explicitly rejected.
            if max_drawdown_pct >= Decimal::ONE {
                return Err(format!(
                    "risk_limits.max_drawdown_pct = {} must be < 1.0 (100%%) — losing everything is not a valid risk parameter",
                    max_drawdown_pct
                ).into());
            }

            let max_total_exposure_pct = parse_decimal(&r.max_total_exposure_pct,
                "risk_limits.max_total_exposure_pct")?;
            // M-7: Exposure limit must be strictly > 0 (0% exposure would block all trading).
            validate_strictly_positive_pct(max_total_exposure_pct,
                "risk_limits.max_total_exposure_pct")?;

            let max_single_position_pct = parse_decimal(&r.max_single_position_pct,
                "risk_limits.max_single_position_pct")?;
            // M-7: Position limit must be strictly > 0.
            validate_strictly_positive_pct(max_single_position_pct,
                "risk_limits.max_single_position_pct")?;

            if r.exchange_failure_threshold == 0 {
                return Err("risk_limits.exchange_failure_threshold must be > 0".into());
            }

            validate_positive_i64(r.exchange_pause_duration_seconds,
                "risk_limits.exchange_pause_duration_seconds")?;

            let stablecoin_depeg_threshold = parse_decimal(&r.stablecoin_depeg_threshold,
                "risk_limits.stablecoin_depeg_threshold")?;
            validate_positive(stablecoin_depeg_threshold,
                "risk_limits.stablecoin_depeg_threshold")?;

            let daily_loss_limit_usd = parse_decimal(&r.daily_loss_limit_usd,
                "risk_limits.daily_loss_limit_usd")?;
            validate_positive(daily_loss_limit_usd,
                "risk_limits.daily_loss_limit_usd")?;

            ValidatedRiskConfig {
                min_net_profit_pct,
                max_equity_staleness_seconds: r.max_equity_staleness_seconds,
                absolute_hard_loss_cap,
                pct_hard_loss_cap,
                max_drawdown_pct,
                max_total_exposure_pct,
                max_single_position_pct,
                exchange_failure_threshold: r.exchange_failure_threshold,
                exchange_pause_duration_seconds: r.exchange_pause_duration_seconds,
                stablecoin_depeg_threshold,
                daily_loss_limit_usd,
            }
        };

        // ── Exchanges ────────────────────────────────────────────────────

        let mut exchanges: HashMap<u16, ValidatedExchangeConfig> = HashMap::new();
        for (section_name, raw_ex) in &raw.exchanges {
            if exchanges.contains_key(&raw_ex.id) {
                return Err(format!(
                    "Duplicate exchange id {} (found in section [exchanges.{}])",
                    raw_ex.id, section_name
                )
                .into());
            }
            if raw_ex.name != *section_name {
                return Err(format!(
                    "Exchange section name '{}' does not match exchange.name '{}'",
                    section_name, raw_ex.name
                )
                .into());
            }
            // Apply environment-variable overrides for secrets.
            let prefix = exchange_env_prefix(&raw_ex.name);
            let api_key = env_override(&format!("{}_API_KEY", prefix))
                .unwrap_or_else(|| raw_ex.api_key.clone());
            let api_secret = env_override(&format!("{}_API_SECRET", prefix))
                .unwrap_or_else(|| raw_ex.api_secret.clone());
            let passphrase = env_override(&format!("{}_PASSPHRASE", prefix))
                .or_else(|| raw_ex.passphrase.clone());

            let validated = ValidatedExchangeConfig {
                id: raw_ex.id,
                name: raw_ex.name.clone(),
                api_key,
                api_secret,
                passphrase,
                wss_url: raw_ex.wss_url.clone(),
                rest_url: raw_ex.rest_url.clone(),
            };
            exchanges.insert(validated.id, validated);
        }

        if exchanges.is_empty() {
            return Err("At least one exchange must be configured under [exchanges.*]".into());
        }

        // H-7: Validate that the number of exchanges does not exceed the u64
        // bitmask limit (64 exchanges).  The bitmask system used in
        // strategies.rs and market_arena.rs can represent at most 64 exchanges
        // (bits 0..63).  Exceeding this would cause silent bitmask overflow.
        if exchanges.len() > MAX_EXCHANGES {
            return Err(
                format!("FATAL: More than {} exchanges configured. The u64 bitmask system supports at most {} exchanges.", MAX_EXCHANGES, MAX_EXCHANGES)
                    .into(),
            );
        }

        // ── Stablecoin ───────────────────────────────────────────────────

        let stablecoin = {
            let s = &raw.stablecoin;
            let depeg_threshold = f64_to_decimal(s.depeg_threshold, "stablecoin.depeg_threshold")?;
            let usdt_max_pct = f64_to_decimal(s.usdt_max_pct, "stablecoin.usdt_max_pct")?;
            let usdc_min_pct = f64_to_decimal(s.usdc_min_pct, "stablecoin.usdc_min_pct")?;

            if depeg_threshold <= Decimal::ZERO || depeg_threshold >= Decimal::ONE {
                return Err(format!(
                    "stablecoin.depeg_threshold = {} must be in (0, 1)",
                    depeg_threshold
                )
                .into());
            }
            if usdt_max_pct < Decimal::ZERO || usdt_max_pct > Decimal::ONE {
                return Err(format!(
                    "stablecoin.usdt_max_pct = {} must be in [0, 1]",
                    usdt_max_pct
                )
                .into());
            }
            if usdc_min_pct < Decimal::ZERO || usdc_min_pct > Decimal::ONE {
                return Err(format!(
                    "stablecoin.usdc_min_pct = {} must be in [0, 1]",
                    usdc_min_pct
                )
                .into());
            }
            // M-1: Cross-field validation — percentages must not overlap.
            if usdt_max_pct + usdc_min_pct > Decimal::ONE {
                return Err("stablecoin usdt_max_pct + usdc_min_pct must be <= 1.0".into());
            }

            ValidatedStablecoinConfig {
                depeg_threshold,
                usdt_max_pct,
                usdc_min_pct,
                monitored_symbols: s.monitored_symbols.clone(),
            }
        };

        // Apply DISCORD_WEBHOOK_URL env override if set.
        let mut discord = raw.discord;
        if let Some(url) = env_override("DISCORD_WEBHOOK_URL") {
            discord.webhook_url = url;
        }

        // ── Friction protections ─────────────────────────────────────────

        let friction_protections = {
            let f = &raw.friction_protections;

            let transfer_gas_fee_usd = parse_decimal(
                &f.transfer_gas_fee_usd,
                "friction_protections.transfer_gas_fee_usd",
            )?;
            validate_positive(transfer_gas_fee_usd,
                "friction_protections.transfer_gas_fee_usd")?;

            let default_taker_fee_pct = parse_decimal(
                &f.default_taker_fee_pct,
                "friction_protections.default_taker_fee_pct",
            )?;
            validate_pct_range(default_taker_fee_pct,
                "friction_protections.default_taker_fee_pct")?;

            // Validate per-exchange fee overrides: each must be > 0.
            for (name, bps) in &f.exchange_taker_fees {
                if *bps == 0 {
                    return Err(format!(
                        "friction_protections.exchange_taker_fees.{} = 0 must be > 0",
                        name
                    )
                    .into());
                }
            }

            ValidatedFrictionProtections {
                transfer_gas_fee_usd,
                fee_aware_enabled: f.fee_aware_enabled,
                default_taker_fee_pct,
                exchange_taker_fees: f.exchange_taker_fees.clone(),
            }
        };

        // ── Deposit addresses ───────────────────────────────────────────
        let deposit_addresses = raw.deposit_addresses;
        // Validate format: non-empty values must start with 0x, be >= 10 chars,
        // and must NOT be the zero-address sentinel (all zeros after 0x).
        for (key, addr) in &deposit_addresses {
            if addr.is_empty() {
                continue; // empty is ok, means not configured
            }
            if !addr.starts_with("0x") || addr.len() < MIN_DEPOSIT_ADDR_LEN {
                return Err(format!(
                    "deposit_addresses.{} = \"{}\" is not a valid blockchain address (must start with 0x, min 10 chars)",
                    key, addr
                ).into());
            }
            // Reject the zero-address sentinel (0x0000...0000).
            // A valid address must have at least one non-zero hex char after "0x".
            let hex_body = &addr[2..];
            let all_zeros = hex_body.chars().all(|c| c == '0');
            if all_zeros {
                return Err(format!(
                    "deposit_addresses.{} is the zero-address sentinel (0x0000...). \
                     Replace it with your REAL verified on-chain deposit address before live deployment.",
                    key
                ).into());
            }
            // Verify all characters after "0x" are valid hex digits.
            if !hex_body.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(format!(
                    "deposit_addresses.{} = \"{}\" contains non-hex characters",
                    key, addr
                ).into());
            }
            if addr.len() > MAX_DEPOSIT_ADDR_LEN {
                return Err(format!(
                    "deposit_addresses.{} = \"{}\" is too long (>{} chars)",
                    key, addr, MAX_DEPOSIT_ADDR_LEN
                ).into());
            }
        }

        tracing::info!(
            exchanges = exchanges.len(),
            "Config loaded and validated successfully"
        );

        Ok(Self {
            force_live_mode: raw.force_live_mode,
            vps: raw.vps_settings,
            discord,
            strategies: ValidatedStrategies {
                cross_exchange,
                triangular,
            },
            risk,
            exchanges,
            stablecoin,
            friction_protections,
            deposit_addresses,
        })
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  Unit tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    /// RAII guard that deletes a temp file on drop.
    struct TempFile {
        path: std::path::PathBuf,
    }

    impl Drop for TempFile {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.path);
        }
    }

    /// Write `content` to a uniquely-named temp file and return (path, guard).
    /// The file is removed when the guard is dropped.
    fn write_temp_toml(content: &str) -> (std::path::PathBuf, TempFile) {
        let n = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("hft_config_test_{}.toml", n));
        fs::write(&path, content).expect("failed to write temp TOML");
        let guard = TempFile { path: path.clone() };
        (path, guard)
    }

    /// Set all secret-related env vars to empty strings so that tests are
    /// isolated from any `.env` file in the project root.  Using empty
    /// strings (instead of `remove_var`) prevents `dotenvy::dotenv()` from
    /// re-populating them, since dotenvy skips variables that already exist.
    fn clear_secret_envs() {
        for key in [
            "BINANCE_API_KEY",
            "BINANCE_API_SECRET",
            "BYBIT_API_KEY",
            "BYBIT_API_SECRET",
            "OKX_API_KEY",
            "OKX_API_SECRET",
            "OKX_PASSPHRASE",
            "GATEIO_API_KEY",
            "GATEIO_API_SECRET",
            "KUCOIN_API_KEY",
            "KUCOIN_API_SECRET",
            "KUCOIN_PASSPHRASE",
            "DISCORD_WEBHOOK_URL",
        ] {
            std::env::set_var(key, "");
        }
    }

    /// A well-formed config that satisfies every validation rule.
    const VALID_TOML: &str = r#"
[vps_settings]
pinned_cpu_core = 2
network_interface_backlog = 4096

[discord]
webhook_url = "https://discord.com/api/webhooks/test/hook"
buffer_capacity = 128

[strategies.cross_exchange]
enabled = true
min_spread_pct = "0.001"
max_target_latency_ms = 50
min_l2_liquidity_usd = "10000.0"
max_slippage_tolerance = "0.0005"

[strategies.triangular]
enabled = true
min_loop_profit_pct = "0.0005"
max_path_length = 4
min_pair_volume_24h = "500000.0"
quote_anchors = ["USDT", "USDC"]

[exchanges.binance]
id = 1
name = "binance"
api_key = "key_binance"
api_secret = "secret_binance"
wss_url = "wss://stream.binance.com/ws"
rest_url = "https://api.binance.com"

[exchanges.okx]
id = 2
name = "okx"
api_key = "key_okx"
api_secret = "secret_okx"
passphrase = "okx_passphrase"
wss_url = "wss://ws.okx.com:8443/ws/v5/public"
rest_url = "https://www.okx.com"

[risk_limits]
min_net_profit_pct = "0.0001"
max_equity_staleness_seconds = 300
absolute_hard_loss_cap = "500.0"
pct_hard_loss_cap = "0.02"
max_drawdown_pct = "0.05"
max_total_exposure_pct = "0.80"
max_single_position_pct = "0.10"
exchange_failure_threshold = 5
exchange_pause_duration_seconds = 60
stablecoin_depeg_threshold = "0.005"

[stablecoin]
depeg_threshold = 0.998
usdt_max_pct = 0.80
usdc_min_pct = 0.20
monitored_symbols = ["USDT/USD", "USDC/USD"]
"#;

    // ── Happy-path tests ─────────────────────────────────────────────────

    #[test]
    fn test_load_valid_config() {
        clear_secret_envs();
        let (path, _guard) = write_temp_toml(VALID_TOML);
        let config = EngineConfig::load_and_validate(&path).unwrap();

        // VPS
        assert_eq!(config.vps.pinned_cpu_core, 2);
        assert_eq!(config.vps.network_interface_backlog, 4096);

        // Discord
        assert_eq!(config.discord.buffer_capacity, 128);
        assert_eq!(config.discord.webhook_url, "https://discord.com/api/webhooks/test/hook");

        // Cross-exchange strategy
        assert!(config.strategies.cross_exchange.enabled);
        assert_eq!(
            config.strategies.cross_exchange.min_spread_pct,
            Decimal::from_str("0.001").unwrap()
        );
        assert_eq!(config.strategies.cross_exchange.max_target_latency_ms, 50);
        assert_eq!(
            config.strategies.cross_exchange.min_l2_liquidity_usd,
            Decimal::from_str("10000.0").unwrap()
        );
        assert_eq!(
            config.strategies.cross_exchange.max_slippage_tolerance,
            Decimal::from_str("0.0005").unwrap()
        );

        // Triangular strategy
        assert!(config.strategies.triangular.enabled);
        assert_eq!(
            config.strategies.triangular.min_loop_profit_pct,
            Decimal::from_str("0.0005").unwrap()
        );
        assert_eq!(config.strategies.triangular.max_path_length, 4);
        assert_eq!(
            config.strategies.triangular.min_pair_volume_24h,
            Decimal::from_str("500000.0").unwrap()
        );
        assert_eq!(config.strategies.triangular.quote_anchors, vec!["USDT", "USDC"]);

        // Exchanges
        assert_eq!(config.exchanges.len(), 2);
        assert!(config.exchanges.contains_key(&1));
        assert!(config.exchanges.contains_key(&2));

        let binance = &config.exchanges[&1];
        assert_eq!(binance.name, "binance");
        assert!(binance.passphrase.is_none());

        let okx = &config.exchanges[&2];
        assert_eq!(okx.name, "okx");
        assert_eq!(okx.passphrase.as_deref(), Some("okx_passphrase"));

        // Risk limits
        assert_eq!(config.risk.exchange_failure_threshold, 5);
        assert_eq!(config.risk.max_equity_staleness_seconds, 300);
        assert_eq!(
            config.risk.pct_hard_loss_cap,
            Decimal::from_str("0.02").unwrap()
        );

        // Stablecoin
        assert_eq!(
            config.stablecoin.depeg_threshold,
            Decimal::from_str("0.998").unwrap()
        );
        assert_eq!(config.stablecoin.monitored_symbols.len(), 2);
    }

    #[test]
    fn test_decimal_precision_preserved() {
        clear_secret_envs();
        let (path, _guard) = write_temp_toml(VALID_TOML);
        let config = EngineConfig::load_and_validate(&path).unwrap();

        // These must be exact Decimal comparisons — no f64 round-trip loss.
        assert_eq!(
            config.strategies.cross_exchange.min_spread_pct,
            Decimal::from_str("0.001").unwrap()
        );
        assert_eq!(
            config.risk.pct_hard_loss_cap,
            Decimal::from_str("0.02").unwrap()
        );
        assert_eq!(
            config.risk.max_total_exposure_pct,
            Decimal::from_str("0.80").unwrap()
        );
        assert_eq!(
            config.stablecoin.depeg_threshold,
            Decimal::from_str("0.998").unwrap()
        );
        assert_eq!(
            config.stablecoin.usdt_max_pct,
            Decimal::from_str("0.80").unwrap()
        );
    }

    #[test]
    fn test_exchange_optional_passphrase() {
        clear_secret_envs();
        let (path, _guard) = write_temp_toml(VALID_TOML);
        let config = EngineConfig::load_and_validate(&path).unwrap();

        // Binance — no passphrase key in TOML → None
        assert!(config.exchanges[&1].passphrase.is_none());
        // OKX — explicit passphrase → Some
        assert_eq!(config.exchanges[&2].passphrase.as_deref(), Some("okx_passphrase"));
    }

    #[test]
    fn test_stablecoin_section_uses_defaults_when_missing() {
        clear_secret_envs();
        let toml = VALID_TOML.replace("\n[stablecoin]\n", "").replace(
            r#"depeg_threshold = 0.998
usdt_max_pct = 0.80
usdc_min_pct = 0.20
monitored_symbols = ["USDT/USD", "USDC/USD"]"#,
            "",
        );
        let (path, _guard) = write_temp_toml(&toml);
        let config = EngineConfig::load_and_validate(&path).unwrap();

        assert_eq!(
            config.stablecoin.depeg_threshold,
            Decimal::from_str("0.998").unwrap()
        );
        assert_eq!(
            config.stablecoin.usdt_max_pct,
            Decimal::from_str("0.80").unwrap()
        );
        assert_eq!(
            config.stablecoin.usdc_min_pct,
            Decimal::from_str("0.20").unwrap()
        );
        assert!(config.stablecoin.monitored_symbols.is_empty());
    }

    #[test]
    fn test_stablecoin_default_impl() {
        let default = StablecoinConfig::default();
        assert!((default.depeg_threshold - 0.998).abs() < f64::EPSILON);
        assert!((default.usdt_max_pct - 0.80).abs() < f64::EPSILON);
        assert!((default.usdc_min_pct - 0.20).abs() < f64::EPSILON);
        assert!(default.monitored_symbols.is_empty());
    }

    // ── Validation-failure tests ─────────────────────────────────────────

    #[test]
    fn test_percentage_above_one_rejected() {
        let toml = VALID_TOML.replace(
            r#"min_spread_pct = "0.001""#,
            r#"min_spread_pct = "1.5""#,
        );
        let (path, _guard) = write_temp_toml(&toml);
        let err = EngineConfig::load_and_validate(&path).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("must be between 0 and 1"),
            "expected pct-range error, got: {}",
            msg
        );
    }

    #[test]
    fn test_negative_percentage_rejected() {
        let toml = VALID_TOML.replace(
            r#"pct_hard_loss_cap = "0.02""#,
            r#"pct_hard_loss_cap = "-0.01""#,
        );
        let (path, _guard) = write_temp_toml(&toml);
        let err = EngineConfig::load_and_validate(&path).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("must be between 0 and 1"),
            "expected pct-range error, got: {}",
            msg
        );
    }

    #[test]
    fn test_non_positive_threshold_rejected() {
        let toml = VALID_TOML.replace(
            r#"min_l2_liquidity_usd = "10000.0""#,
            r#"min_l2_liquidity_usd = "0""#,
        );
        let (path, _guard) = write_temp_toml(&toml);
        let err = EngineConfig::load_and_validate(&path).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("must be strictly greater than 0"),
            "expected positive error, got: {}",
            msg
        );
    }

    #[test]
    fn test_negative_liquidity_rejected() {
        let toml = VALID_TOML.replace(
            r#"absolute_hard_loss_cap = "500.0""#,
            r#"absolute_hard_loss_cap = "-100""#,
        );
        let (path, _guard) = write_temp_toml(&toml);
        let err = EngineConfig::load_and_validate(&path).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("must be strictly greater than 0"),
            "expected positive error, got: {}",
            msg
        );
    }

    #[test]
    fn test_duplicate_exchange_id_rejected() {
        // Make OKX share Binance's id
        let toml = VALID_TOML.replace("[exchanges.okx]\nid = 2", "[exchanges.okx]\nid = 1");
        let (path, _guard) = write_temp_toml(&toml);
        let err = EngineConfig::load_and_validate(&path).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("Duplicate exchange id"),
            "expected duplicate-id error, got: {}",
            msg
        );
    }

    #[test]
    fn test_exchange_name_mismatch_rejected() {
        let toml = VALID_TOML.replace("name = \"binance\"", "name = \"Binance\"");
        let (path, _guard) = write_temp_toml(&toml);
        let err = EngineConfig::load_and_validate(&path).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("does not match exchange.name"),
            "expected name-mismatch error, got: {}",
            msg
        );
    }

    #[test]
    fn test_empty_exchanges_rejected() {
        // Replace exchange section headers with a single empty [exchanges] table
        let toml = VALID_TOML
            .lines()
            .filter(|l| !l.starts_with("[exchanges.") && !l.contains("api_key") && !l.contains("api_secret")
                && !l.contains("wss_url") && !l.contains("rest_url")
                && !l.contains("passphrase") && !l.contains("name = \"")
                && !l.contains("id = "))
            .collect::<Vec<_>>()
            .join("\n")
            .replacen("[strategies", "[exchanges]\n\n[strategies", 1);
        let (path, _guard) = write_temp_toml(&toml);
        let err = EngineConfig::load_and_validate(&path).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("At least one exchange"),
            "expected empty-exchange error, got: {}",
            msg
        );
    }

    #[test]
    fn test_invalid_decimal_string_rejected() {
        let toml = VALID_TOML.replace(
            r#"min_spread_pct = "0.001""#,
            r#"min_spread_pct = "not_a_number""#,
        );
        let (path, _guard) = write_temp_toml(&toml);
        let err = EngineConfig::load_and_validate(&path).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("Failed to parse"),
            "expected parse error, got: {}",
            msg
        );
    }

    #[test]
    fn test_max_equity_staleness_must_be_positive() {
        let toml = VALID_TOML.replace(
            "max_equity_staleness_seconds = 300",
            "max_equity_staleness_seconds = 0",
        );
        let (path, _guard) = write_temp_toml(&toml);
        let err = EngineConfig::load_and_validate(&path).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("must be strictly greater than 0"),
            "expected positive i64 error, got: {}",
            msg
        );
    }

    #[test]
    fn test_exchange_pause_duration_must_be_positive() {
        let toml = VALID_TOML.replace(
            "exchange_pause_duration_seconds = 60",
            "exchange_pause_duration_seconds = -10",
        );
        let (path, _guard) = write_temp_toml(&toml);
        let err = EngineConfig::load_and_validate(&path).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("must be strictly greater than 0"),
            "expected positive i64 error, got: {}",
            msg
        );
    }

    #[test]
    fn test_exchange_failure_threshold_zero_rejected() {
        let toml = VALID_TOML.replace(
            "exchange_failure_threshold = 5",
            "exchange_failure_threshold = 0",
        );
        let (path, _guard) = write_temp_toml(&toml);
        let err = EngineConfig::load_and_validate(&path).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("must be > 0"),
            "expected failure-threshold error, got: {}",
            msg
        );
    }

    #[test]
    fn test_triangular_max_path_length_too_short() {
        let toml = VALID_TOML.replace("max_path_length = 4", "max_path_length = 2");
        let (path, _guard) = write_temp_toml(&toml);
        let err = EngineConfig::load_and_validate(&path).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("must be >= 3"),
            "expected path-length error, got: {}",
            msg
        );
    }

    #[test]
    fn test_triangular_empty_quote_anchors_rejected() {
        let toml = VALID_TOML.replace(
            r#"quote_anchors = ["USDT", "USDC"]"#,
            r#"quote_anchors = []"#,
        );
        let (path, _guard) = write_temp_toml(&toml);
        let err = EngineConfig::load_and_validate(&path).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("at least one entry"),
            "expected empty-anchors error, got: {}",
            msg
        );
    }

    #[test]
    fn test_missing_file_returns_error() {
        let result = EngineConfig::load_and_validate("/nonexistent/path/config.toml");
        assert!(result.is_err());
    }

    #[test]
    fn test_malformed_toml_returns_error() {
        let toml = "this is not valid [toml {{{";
        let (path, _guard) = write_temp_toml(toml);
        let result = EngineConfig::load_and_validate(&path);
        assert!(result.is_err());
    }

    #[test]
    fn test_friction_protections_defaults_when_missing() {
        clear_secret_envs();
        // VALID_TOML has no [friction_protections] → serde default is used.
        let (path, _guard) = write_temp_toml(VALID_TOML);
        let config = EngineConfig::load_and_validate(&path).unwrap();

        assert!(config.friction_protections.fee_aware_enabled);
        assert_eq!(
            config.friction_protections.transfer_gas_fee_usd,
            Decimal::from_str("2.00").unwrap()
        );
        assert_eq!(
            config.friction_protections.default_taker_fee_pct,
            Decimal::from_str("0.0010").unwrap()
        );
        assert!(config.friction_protections.exchange_taker_fees.is_empty());
    }

    #[test]
    fn test_friction_protections_parsed_from_toml() {
        clear_secret_envs();
        let toml = VALID_TOML.replace(
            "[stablecoin]",
            r#"[friction_protections]
transfer_gas_fee_usd = "3.50"
fee_aware_enabled = false
default_taker_fee_pct = "0.0008"

[friction_protections.exchange_taker_fees]
binance = 7
okx = 6

[stablecoin]"#,
        );
        let (path, _guard) = write_temp_toml(&toml);
        let config = EngineConfig::load_and_validate(&path).unwrap();

        assert!(!config.friction_protections.fee_aware_enabled);
        assert_eq!(
            config.friction_protections.transfer_gas_fee_usd,
            Decimal::from_str("3.50").unwrap()
        );
        assert_eq!(
            config.friction_protections.default_taker_fee_pct,
            Decimal::from_str("0.0008").unwrap()
        );
        assert_eq!(config.friction_protections.exchange_taker_fees["binance"], 7);
        assert_eq!(config.friction_protections.exchange_taker_fees["okx"], 6);
    }

    #[test]
    fn test_friction_zero_exchange_fee_rejected() {
        clear_secret_envs();
        let toml = VALID_TOML.replace(
            "[stablecoin]",
            r#"[friction_protections]
transfer_gas_fee_usd = "2.00"
fee_aware_enabled = true
default_taker_fee_pct = "0.0010"

[friction_protections.exchange_taker_fees]
binance = 0

[stablecoin]"#,
        );
        let (path, _guard) = write_temp_toml(&toml);
        let err = EngineConfig::load_and_validate(&path).unwrap_err();
        assert!(
            err.to_string().contains("must be > 0"),
            "expected zero-fee rejection, got: {}",
            err
        );
    }
}