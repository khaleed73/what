//! Dust Manager — Auto-Convert Tiny Fractional Remnants
//!
//! The spec mentions: "Dust Management — Auto-converting tiny fractional
//! crypto remnants (dust) to BNB or native tokens via exchange APIs"
//!
//! This module tracks small residual balances across exchanges and generates
//! conversion requests when dust accumulates above configurable thresholds.

use rust_decimal::Decimal;
use rust_decimal_macros::dec;
use std::collections::HashMap;

/// Default dust threshold in USD — balances worth less than this are dust.
const DEFAULT_DUST_THRESHOLD_USD: Decimal = dec!(0.50);

/// Default minimum total dust value before triggering a conversion sweep.
const DEFAULT_SWEEP_THRESHOLD_USD: Decimal = dec!(5.00);

/// A dust entry for a single token on a single exchange.
#[derive(Debug, Clone)]
pub struct DustEntry {
    pub exchange_id: u16,
    pub token_symbol: String,
    pub quantity: Decimal,
    pub estimated_usd_value: Decimal,
}

/// A dust conversion request.
#[derive(Debug, Clone)]
pub struct DustConversionRequest {
    pub exchange_id: u16,
    pub token_symbol: String,
    pub quantity: Decimal,
    pub target_symbol: String, // e.g. "BNB", "OKB", "MNT"
}

/// Manages dust detection and conversion scheduling.
///
/// Dust is defined as token balances below a configurable USD threshold
/// that are too small to trade profitably.
pub struct DustManager {
    /// Per-exchange dust threshold in USD.
    dust_threshold_usd: Decimal,
    /// Minimum total dust value to trigger a sweep.
    sweep_threshold_usd: Decimal,
    /// M-18: Minimum withdrawal amount in USD. Dust entries below this
    /// value are not included in conversion requests.
    min_withdrawal_usd: Decimal,
    /// C-13 fix: Target tokens wrapped in RwLock for thread safety.
    target_tokens: std::sync::RwLock<HashMap<u16, String>>,
    /// Accumulated dust entries.
    dust_inventory: std::sync::Mutex<Vec<DustEntry>>,
}

impl DustManager {
    /// Default minimum withdrawal amount in USD (most exchanges: $10-20).
    const DEFAULT_MIN_WITHDRAWAL_USD: Decimal = dec!(10.0);

    /// Creates a new DustManager with default thresholds.
    pub fn new() -> Self {
        Self {
            dust_threshold_usd: DEFAULT_DUST_THRESHOLD_USD,
            sweep_threshold_usd: DEFAULT_SWEEP_THRESHOLD_USD,
            min_withdrawal_usd: Self::DEFAULT_MIN_WITHDRAWAL_USD,
            target_tokens: std::sync::RwLock::new(HashMap::new()),
            dust_inventory: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// Creates with custom thresholds.
    pub fn with_thresholds(dust_threshold: Decimal, sweep_threshold: Decimal) -> Self {
        Self {
            dust_threshold_usd: dust_threshold,
            sweep_threshold_usd: sweep_threshold,
            min_withdrawal_usd: Self::DEFAULT_MIN_WITHDRAWAL_USD,
            target_tokens: std::sync::RwLock::new(HashMap::new()),
            dust_inventory: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// Register the target conversion token for an exchange.
    ///
    /// Example: Binance → "BNB", OKX → "OKB", Bybit → "MNT"
    pub fn set_target_token(&self, exchange_id: u16, token: &str) {
        self.target_tokens.write().unwrap_or_else(|e| e.into_inner()).insert(exchange_id, token.to_uppercase());
    }

    /// Ingest a balance update. If the balance is below dust threshold,
    /// it's added to the dust inventory.
    /// C-5 fix: Also removes entries when balance rises above threshold.
    #[inline]
    pub fn update_balance(
        &self,
        exchange_id: u16,
        token_symbol: &str,
        quantity: Decimal,
        price_usd: Decimal,
    ) {
        if quantity <= Decimal::ZERO {
            return;
        }

        let usd_value = quantity * price_usd;

        if usd_value < self.dust_threshold_usd {
            // This is dust.
            let mut inventory = self.dust_inventory.lock().unwrap_or_else(|e| e.into_inner());

            // Update existing entry or add new one.
            if let Some(entry) = inventory.iter_mut().find(|e| {
                e.exchange_id == exchange_id && e.token_symbol == token_symbol.to_uppercase()
            }) {
                entry.quantity = quantity;
                entry.estimated_usd_value = usd_value;
            } else {
                inventory.push(DustEntry {
                    exchange_id,
                    token_symbol: token_symbol.to_uppercase(),
                    quantity,
                    estimated_usd_value: usd_value,
                });
            }
        } else {
            // C-5: Balance is above dust threshold — remove from inventory
            // if it was previously tracked as dust.
            let mut inventory = self.dust_inventory.lock().unwrap_or_else(|e| e.into_inner());
            inventory.retain(|e| !(e.exchange_id == exchange_id && e.token_symbol == token_symbol.to_uppercase()));
        }
    }

    /// Check if total dust exceeds sweep threshold and generate conversion requests.
    pub fn evaluate_and_generate_requests(&self) -> Vec<DustConversionRequest> {
        let inventory = self.dust_inventory.lock().unwrap_or_else(|e| e.into_inner());
        let total_dust: Decimal = inventory.iter().map(|e| e.estimated_usd_value).sum();

        if total_dust < self.sweep_threshold_usd {
            return vec![];
        }

        inventory
            .iter()
            .filter_map(|entry| {
                // M-18: Skip entries below the minimum withdrawal amount.
                if entry.estimated_usd_value < self.min_withdrawal_usd {
                    return None;
                }
                let read_guard = self.target_tokens.read().unwrap_or_else(|e| e.into_inner());
                let target = read_guard.get(&entry.exchange_id)?;
                Some(DustConversionRequest {
                    exchange_id: entry.exchange_id,
                    token_symbol: entry.token_symbol.clone(),
                    quantity: entry.quantity,
                    target_symbol: target.clone(),
                })
            })
            .collect()
    }

    /// Clear the dust inventory (called after a successful sweep).
    pub fn clear_inventory(&self) {
        self.dust_inventory.lock().unwrap_or_else(|e| e.into_inner()).clear();
    }

    /// Returns the current dust inventory.
    pub fn get_inventory(&self) -> Vec<DustEntry> {
        self.dust_inventory.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Returns the total estimated dust value in USD.
    pub fn total_dust_usd(&self) -> Decimal {
        let inventory = self.dust_inventory.lock().unwrap_or_else(|e| e.into_inner());
        inventory.iter().map(|e| e.estimated_usd_value).sum()
    }
}

impl Default for DustManager {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rust_decimal_macros::dec;

    fn make_manager() -> DustManager {
        let mgr = DustManager::with_thresholds(dec!(1.0), dec!(3.0));
        mgr.set_target_token(1, "BNB");
        mgr
    }

    #[test]
    fn test_no_dust_above_threshold() {
        let mgr = make_manager();
        // $5 worth — above dust threshold of $1
        mgr.update_balance(1, "SOL", dec!(0.05), dec!(100)); // $5
        assert!(mgr.get_inventory().is_empty());
    }

    #[test]
    fn test_dust_detected() {
        let mgr = make_manager();
        // $0.50 worth — below dust threshold of $1
        mgr.update_balance(1, "SOL", dec!(0.005), dec!(100)); // $0.50
        let inv = mgr.get_inventory();
        assert_eq!(inv.len(), 1);
        assert_eq!(inv[0].token_symbol, "SOL");
    }

    #[test]
    fn test_sweep_below_threshold() {
        let mgr = make_manager();
        mgr.update_balance(1, "SOL", dec!(0.005), dec!(100)); // $0.50
        mgr.update_balance(1, "ETH", dec!(0.0001), dec!(2000)); // $0.20
        // Total = $0.70 < $3.00 sweep threshold
        let reqs = mgr.evaluate_and_generate_requests();
        assert!(reqs.is_empty());
    }

    #[test]
    fn test_sweep_above_threshold() {
        let mgr = make_manager();
        // Add enough dust to exceed $3 sweep threshold
        for i in 0..10 {
            let symbol = format!("TOKEN{}", i);
            mgr.update_balance(1, &symbol, dec!(0.01), dec!(50)); // $0.50 each
        }
        // Total = $5.00 > $3.00 sweep threshold
        let reqs = mgr.evaluate_and_generate_requests();
        assert_eq!(reqs.len(), 10);
        assert_eq!(reqs[0].target_symbol, "BNB");
    }

    #[test]
    fn test_clear_inventory() {
        let mgr = make_manager();
        mgr.update_balance(1, "SOL", dec!(0.005), dec!(100));
        assert!(!mgr.get_inventory().is_empty());
        mgr.clear_inventory();
        assert!(mgr.get_inventory().is_empty());
    }

    #[test]
    fn test_total_dust_usd() {
        let mgr = make_manager();
        mgr.update_balance(1, "SOL", dec!(0.005), dec!(100)); // $0.50
        mgr.update_balance(1, "ETH", dec!(0.0001), dec!(2000)); // $0.20
        let total = mgr.total_dust_usd();
        assert!((total - dec!(0.70)).abs() < dec!(0.01));
    }
}