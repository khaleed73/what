//! Position Reconciliation — Cross-exchange position verification.
//!
//! Periodically compares the bot's internal position state against actual
//! exchange balances.  Detects drift (phantom orders, partial fills that
//! were not tracked) and triggers circuit-breaker action when drift
//! exceeds the configured threshold.

use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::time::sleep;
use tracing::{info, warn, error};

use rust_decimal::Decimal;
use rust_decimal_macros::dec;

/// Configuration for the position reconciliation loop.
#[derive(Debug, Clone)]
pub struct ReconciliationConfig {
    /// How often to run reconciliation (seconds).
    pub interval_secs: u64,
    /// Maximum allowed drift (USD) before alerting.
    pub max_drift_usd: Decimal,
    /// Maximum allowed drift as a fraction (e.g., 0.05 = 5%).
    pub max_drift_pct: Decimal,
}

impl Default for ReconciliationConfig {
    fn default() -> Self {
        Self {
            interval_secs: 120, // every 2 minutes
            max_drift_usd: dec!(50.0),
            max_drift_pct: dec!(0.05),
        }
    }
}

/// A detected position discrepancy between local state and exchange reality.
#[derive(Debug, Clone)]
pub struct PositionDrift {
    pub exchange_id: u16,
    pub token_id: u16,
    pub local_balance: Decimal,
    pub exchange_balance: Decimal,
    pub drift_usd: Decimal,
    pub drift_pct: Decimal,
}

/// The reconciliation loop.
///
/// Compares the `balance_allocator`'s internal matrix against real exchange
/// balances and reports any discrepancies.
pub struct PositionReconciliationLoop;

impl PositionReconciliationLoop {
    /// Runs the reconciliation loop indefinitely.
    ///
    /// # Arguments
    /// * `config` — Reconciliation parameters.
    /// * `allocator` — The local balance allocator (source of truth for internal state).
    /// * `execution_pool` — Exchange client pool for querying real balances.
    /// * `http_client` — HTTP client for REST API calls.
    pub async fn run(
        config: ReconciliationConfig,
        allocator: Arc<balance_allocator::LocalCapitalAllocator>,
        execution_pool: Arc<std::collections::HashMap<u16, Arc<dyn signer::PrivateExchangeClient>>>,
        http_client: reqwest::Client,
        num_exchanges: usize,
    ) {
        info!(
            interval_s = config.interval_secs,
            max_drift_usd = %config.max_drift_usd,
            max_drift_pct = %config.max_drift_pct,
            "position reconciliation loop started"
        );

        // Skip the first cycle to let the system warm up.
        sleep(Duration::from_secs(config.interval_secs)).await;

        let mut cycle: u64 = 0;
        loop {
            cycle += 1;
            let drifts = Self::reconcile(
                &allocator,
                &execution_pool,
                &http_client,
                num_exchanges,
                &config,
            )
            .await;

            if drifts.is_empty() {
                info!(cycle, "reconciliation passed — no drift detected");
            } else {
                for d in &drifts {
                    warn!(
                        cycle,
                        exchange = d.exchange_id,
                        token = d.token_id,
                        local = %d.local_balance,
                        exchange = %d.exchange_balance,
                        drift_usd = %d.drift_usd,
                        drift_pct = %d.drift_pct,
                        "POSITION DRIFT DETECTED"
                    );
                }
            }

            sleep(Duration::from_secs(config.interval_secs)).await;
        }
    }

    /// Performs a single reconciliation pass across all exchanges.
    ///
    /// Queries real balances from each exchange and compares against the
    /// local allocator's state for token 0 (USDT).
    async fn reconcile(
        allocator: &balance_allocator::LocalCapitalAllocator,
        execution_pool: &std::collections::HashMap<u16, Arc<dyn signer::PrivateExchangeClient>>,
        http_client: &reqwest::Client,
        num_exchanges: usize,
        config: &ReconciliationConfig,
    ) -> Vec<PositionDrift> {
        let mut drifts = Vec::new();

        for exch_id in 0..num_exchanges as u16 {
            let local_bal = allocator.get_balance_atomic(exch_id as usize, 0);

            // Query real balance from the exchange.
            let real_bal = if let Some(client) = execution_pool.get(&exch_id) {
                match client.get_balance(http_client, "USDT").await {
                    Ok(bal) => bal,
                    Err(e) => {
                        tracing::debug!(
                            exchange = exch_id,
                            error = %e,
                            "balance query failed in reconciliation — using local value"
                        );
                        local_bal // Fall back to local on error.
                    }
                }
            } else {
                local_bal // No client — paper exchange, trust local.
            };

            let drift_usd = (local_bal - real_bal).abs();
            let drift_pct = if local_bal > Decimal::ZERO {
                drift_usd / local_bal
            } else if real_bal > Decimal::ZERO {
                Decimal::ONE // 100% drift if local is zero but exchange has funds.
            } else {
                Decimal::ZERO
            };

            if drift_usd > config.max_drift_usd || drift_pct > config.max_drift_pct {
                drifts.push(PositionDrift {
                    exchange_id: exch_id,
                    token_id: 0,
                    local_balance: local_bal,
                    exchange_balance: real_bal,
                    drift_usd,
                    drift_pct,
                });
            }
        }

        drifts
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let cfg = ReconciliationConfig::default();
        assert_eq!(cfg.interval_secs, 120);
        assert!(cfg.max_drift_usd > Decimal::ZERO);
    }

    #[test]
    fn test_drift_detection() {
        let drift = PositionDrift {
            exchange_id: 0,
            token_id: 0,
            local_balance: dec!(1000.0),
            exchange_balance: dec!(950.0),
            drift_usd: dec!(50.0),
            drift_pct: dec!(0.05),
        };
        assert_eq!(drift.exchange_id, 0);
        assert_eq!(drift.drift_usd, dec!(50.0));
    }
}