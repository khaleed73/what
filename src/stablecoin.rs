use chrono::Utc;
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing;

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

pub struct StablecoinConfig {
    /// Price below which a stablecoin is considered depegged (e.g. 0.998)
    pub depeg_threshold: Decimal,
    /// Maximum allowed fraction of capital held in USDT (e.g. 0.80)
    pub usdt_max_pct: Decimal,
    /// Minimum required fraction of capital held in USDC (e.g. 0.20)
    pub usdc_min_pct: Decimal,
    /// Symbols to monitor for depeg events
    pub monitored_symbols: Vec<String>,
}

impl Default for StablecoinConfig {
    fn default() -> Self {
        Self {
            depeg_threshold: Decimal::new(998, 3), // 0.998
            usdt_max_pct: Decimal::new(80, 2),     // 0.80
            usdc_min_pct: Decimal::new(20, 2),     // 0.20
            monitored_symbols: vec![
                "USDT".to_string(),
                "USDC".to_string(),
                "DAI".to_string(),
            ],
        }
    }
}

// ---------------------------------------------------------------------------
// Price snapshot
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StablecoinPrice {
    pub symbol: String,
    pub price: Decimal,
    pub exchange: String,
    pub timestamp: i64,
}

// ---------------------------------------------------------------------------
// Runtime state
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StablecoinState {
    /// Latest known prices keyed by symbol
    pub prices: HashMap<String, StablecoinPrice>,
    /// True when at least one monitored coin has depegged
    pub depeg_active: bool,
    /// Symbol of the first depegged coin detected, if any
    pub depegged_coin: Option<String>,
    /// Current USDT holdings (in USD terms)
    pub usdt_held: Decimal,
    /// Current USDC holdings (in USD terms)
    pub usdc_held: Decimal,
    /// Current DAI holdings (in USD terms)
    pub dai_held: Decimal,
    /// Total portfolio capital used for percentage calculations
    pub total_capital: Decimal,
}

impl Default for StablecoinState {
    fn default() -> Self {
        Self {
            prices: HashMap::new(),
            depeg_active: false,
            depegged_coin: None,
            usdt_held: Decimal::ZERO,
            usdc_held: Decimal::ZERO,
            dai_held: Decimal::ZERO,
            total_capital: Decimal::ZERO,
        }
    }
}

// ---------------------------------------------------------------------------
// Rotation recommendation
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationRecommendation {
    pub from_coin: String,
    pub to_coin: String,
    pub amount: Decimal,
    pub reason: String,
}

// ---------------------------------------------------------------------------
// Monitor
// ---------------------------------------------------------------------------

pub struct StablecoinMonitor {
    config: StablecoinConfig,
    state: Arc<RwLock<StablecoinState>>,
}

impl StablecoinMonitor {
    pub fn new(config: StablecoinConfig) -> Self {
        Self {
            config,
            state: Arc::new(RwLock::new(StablecoinState::default())),
        }
    }

    /// Ingest a new price for `symbol` and re-evaluate depeg status across all
    /// monitored coins.
    pub async fn update_price(&self, symbol: &str, price: Decimal, exchange: &str) {
        let now = Utc::now().timestamp_millis();
        let entry = StablecoinPrice {
            symbol: symbol.to_uppercase(),
            price,
            exchange: exchange.to_string(),
            timestamp: now,
        };

        let mut state = self.state.write().await;
        state.prices.insert(symbol.to_uppercase(), entry);

        // Check every monitored symbol for depeg.
        let mut any_depegged = false;
        let mut first_depegged: Option<String> = None;

        for sym in &self.config.monitored_symbols {
            if let Some(sp) = state.prices.get(sym) {
                if sp.price < self.config.depeg_threshold {
                    any_depegged = true;
                    if first_depegged.is_none() {
                        first_depegged = Some(sym.clone());
                    }
                }
            }
        }

        if any_depegged {
            if !state.depeg_active {
                tracing::warn!(
                    depegged_coin = ?first_depegged,
                    "DEPEG detected – risk controls activated"
                );
            }
            state.depeg_active = true;
            state.depegged_coin = first_depegged;
        } else {
            if state.depeg_active {
                tracing::info!("All stablecoins back above threshold – depeg cleared");
            }
            state.depeg_active = false;
            state.depegged_coin = None;
        }
    }

    /// Record current stablecoin holdings.
    pub async fn update_holdings(&self, usdt: Decimal, usdc: Decimal, dai: Decimal, total: Decimal) {
        let mut state = self.state.write().await;
        state.usdt_held = usdt;
        state.usdc_held = usdc;
        state.dai_held = dai;
        state.total_capital = total;
    }

    /// Returns `true` when a depeg event is currently active.
    pub async fn is_depeg_active(&self) -> bool {
        self.state.read().await.depeg_active
    }

    /// Check concentration limits.
    ///
    /// Returns `true` when all concentration rules are satisfied, `false` when
    /// at least one rule is breached.
    pub async fn check_concentration(&self) -> bool {
        let state = self.state.read().await;

        if state.total_capital <= Decimal::ZERO {
            tracing::debug!("total_capital is zero or negative; skipping concentration check");
            return true;
        }

        let usdt_pct = state.usdt_held / state.total_capital;
        let usdc_pct = state.usdc_held / state.total_capital;

        let mut ok = true;

        if usdt_pct > self.config.usdt_max_pct {
            tracing::warn!(
                usdt_pct = %usdt_pct,
                usdt_max_pct = %self.config.usdt_max_pct,
                "USDT concentration exceeds limit"
            );
            ok = false;
        }

        if usdc_pct < self.config.usdc_min_pct {
            tracing::warn!(
                usdc_pct = %usdc_pct,
                usdc_min_pct = %self.config.usdc_min_pct,
                "USDC concentration below minimum"
            );
            ok = false;
        }

        ok
    }

    /// If USDT is over-concentrated, recommend rotating the excess to USDC.
    ///
    /// The recommended amount is:
    /// ```text
    /// excess = usdt_held - total_capital * usdt_max_pct
    /// ```
    pub async fn get_rotation_recommendation(&self) -> Option<RotationRecommendation> {
        let state = self.state.read().await;

        if state.total_capital <= Decimal::ZERO {
            return None;
        }

        let usdt_pct = state.usdt_held / state.total_capital;

        if usdt_pct <= self.config.usdt_max_pct {
            return None;
        }

        let max_usdt = state.total_capital * self.config.usdt_max_pct;
        let excess = state.usdt_held - max_usdt;

        if excess <= Decimal::ZERO {
            return None;
        }

        // Convert Decimal percentages to human-readable form: multiply by 100.
        let usdt_pct_display = usdt_pct * Decimal::from(100u32);
        let max_pct_display = self.config.usdt_max_pct * Decimal::from(100u32);

        Some(RotationRecommendation {
            from_coin: "USDT".to_string(),
            to_coin: "USDC".to_string(),
            amount: excess,
            reason: format!(
                "USDT at {}% of capital exceeds {}% cap; rotate {} to USDC",
                usdt_pct_display, max_pct_display, excess,
            ),
        })
    }

    /// Return a clone of the full internal state.
    pub async fn get_state(&self) -> StablecoinState {
        self.state.read().await.clone()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rust_decimal_macros::dec;
    use std::str::FromStr;

    fn default_config() -> StablecoinConfig {
        StablecoinConfig::default()
    }

    #[tokio::test]
    async fn test_no_depeg_at_normal_price() {
        let monitor = StablecoinMonitor::new(default_config());

        monitor.update_price("USDT", dec!(1.000), "binance").await;
        monitor.update_price("USDC", dec!(0.9999), "binance").await;
        monitor.update_price("DAI", dec!(1.0001), "binance").await;

        assert!(!monitor.is_depeg_active().await);

        let state = monitor.get_state().await;
        assert!(!state.depeg_active);
        assert!(state.depegged_coin.is_none());
    }

    #[tokio::test]
    async fn test_depeg_detection() {
        let monitor = StablecoinMonitor::new(default_config());

        // All healthy first
        monitor.update_price("USDT", dec!(1.000), "binance").await;
        monitor.update_price("USDC", dec!(1.000), "binance").await;
        monitor.update_price("DAI", dec!(1.000), "binance").await;

        assert!(!monitor.is_depeg_active().await);

        // USDT drops below 0.998
        monitor.update_price("USDT", dec!(0.997), "binance").await;

        assert!(monitor.is_depeg_active().await);
        let state = monitor.get_state().await;
        assert!(state.depeg_active);
        assert_eq!(state.depegged_coin.as_deref(), Some("USDT"));
    }

    #[tokio::test]
    async fn test_depeg_clears() {
        let monitor = StablecoinMonitor::new(default_config());

        // Trigger depeg
        monitor.update_price("USDT", dec!(0.995), "binance").await;
        monitor.update_price("USDC", dec!(1.000), "binance").await;
        monitor.update_price("DAI", dec!(1.000), "binance").await;

        assert!(monitor.is_depeg_active().await);

        // Bring USDT back above threshold
        monitor.update_price("USDT", dec!(0.999), "binance").await;

        assert!(!monitor.is_depeg_active().await);
        let state = monitor.get_state().await;
        assert!(!state.depeg_active);
        assert!(state.depegged_coin.is_none());
    }

    #[tokio::test]
    async fn test_concentration_ok() {
        let monitor = StablecoinMonitor::new(default_config());

        // 70% USDT, 20% USDC, 10% DAI – within limits
        monitor
            .update_holdings(dec!(7000.0), dec!(2000.0), dec!(1000.0), dec!(10000.0))
            .await;

        assert!(monitor.check_concentration().await);
    }

    #[tokio::test]
    async fn test_concentration_too_much_usdt() {
        let monitor = StablecoinMonitor::new(default_config());

        // 90% USDT, 5% USDC, 5% DAI – USDT exceeds 80% cap, USDC below 20% min
        monitor
            .update_holdings(dec!(9000.0), dec!(500.0), dec!(500.0), dec!(10000.0))
            .await;

        assert!(!monitor.check_concentration().await);
    }

    #[tokio::test]
    async fn test_rotation_recommendation() {
        let monitor = StablecoinMonitor::new(default_config());

        // 90% USDT – excess over 80% cap = 1000
        monitor
            .update_holdings(dec!(9000.0), dec!(500.0), dec!(500.0), dec!(10000.0))
            .await;

        let rec = monitor.get_rotation_recommendation().await;
        assert!(rec.is_some());

        let rec = rec.unwrap();
        assert_eq!(rec.from_coin, "USDT");
        assert_eq!(rec.to_coin, "USDC");
        assert_eq!(rec.amount, Decimal::from_str("1000.0").unwrap());
        assert!(rec.reason.contains("USDT at 90"));
    }
}