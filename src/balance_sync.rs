// balance_sync.rs — Real Exchange Balance Synchronizer
//
// In live trading mode, the bot needs to know the ACTUAL balances on each
// exchange to compute correct lot sizes and detect capital starvation.
// This module queries each exchange's private REST API for USDT balance
// at boot and every N seconds, then atomically updates the LocalCapitalAllocator.

use std::sync::Arc;
use std::time::Duration;

use rust_decimal::Decimal;
use tracing::{error, info, warn};

use crate::balance_allocator::LocalCapitalAllocator;
use crate::signer::PrivateExchangeClient;

/// Query a single exchange's balance for the given token symbol and update the allocator.
///
/// **FIX**: The token symbol is resolved from the `LocalCapitalAllocator` token
/// registry using `token_id`.  This was previously hardcoded to "USDT", which
/// meant the sync loop could never be used for BTC, ETH, or other tokens.
async fn sync_exchange_balance(
    client: &dyn PrivateExchangeClient,
    http: &reqwest::Client,
    exchange_id: u16,
    allocator: &LocalCapitalAllocator,
    token_id: usize,
) -> Result<Decimal, String> {
    // Resolve the token symbol from the allocator's registry.
    // Fall back to "USDT" if the token_id is not registered (should not happen
    // in normal operation since USDT is always registered at id 0).
    let symbol = allocator
        .get_symbol(token_id as u16)
        .unwrap_or_else(|| {
            tracing::warn!(
                token_id,
                "balance_sync: unknown token_id, falling back to USDT — configure token registry correctly"
            );
            "USDT".to_string()
        });
    let balance = client.get_balance(http, &symbol).await?;

    // M-9: Detect significant balance drift between exchange-reported and tracked values.
    let tracked = allocator.get_balance_atomic(exchange_id as usize, token_id);
    if tracked > Decimal::ZERO {
        let abs_diff = (balance - tracked).abs();
        let drift_pct = abs_diff / tracked;
        if drift_pct > rust_decimal::Decimal::from_str("0.05").unwrap_or_default() {
            tracing::error!(
                exchange_id,
                token_id,
                exchange_balance = %balance,
                tracked_balance = %tracked,
                drift_pct = %drift_pct,
                "M-9: Balance drift > 5% detected — exchange-reported balance differs significantly from tracked"
            );
        }
    }

    allocator.update_balance_atomic(exchange_id as usize, token_id, balance);
    Ok(balance)
}

/// Run a one-time boot sync across all exchanges.
/// Returns the total USDT across all exchanges.
///
/// **FIX**: On sync failure, the previous balance is PRESERVED (not zeroed).
/// Zeroing the balance would cause the bot to think it has no capital on that
/// exchange, leading to missed trades or incorrect position sizing.
pub async fn boot_sync(
    clients: &std::collections::HashMap<u16, Arc<dyn PrivateExchangeClient>>,
    http: &reqwest::Client,
    allocator: &LocalCapitalAllocator,
    token_id: usize,
) -> Decimal {
    let mut total = Decimal::ZERO;

    for (&exchange_id, client) in clients {
        match sync_exchange_balance(client.as_ref(), http, exchange_id, allocator, token_id).await {
            Ok(bal) => {
                info!(exchange = exchange_id, balance = %bal, token_id, "boot balance sync OK");
                total += bal;
            }
            Err(e) => {
                // CRITICAL FIX: Do NOT set balance to zero on failure.
                // The allocator may already have a known balance from config
                // or a previous session.  Zeroing it would cause the execution
                // engine to miscalculate position sizes and potentially miss
                // profitable trades or, worse, over-leverage.
                error!(
                    exchange = exchange_id,
                    error = %e,
                    "boot balance sync FAILED — preserving previous balance (NOT zeroing)"
                );
            }
        }
    }

    info!(total_usdt = %total, exchanges = clients.len(), "boot balance sync complete");
    total
}

/// Run the periodic background balance sync loop.
/// Queries all exchanges every `interval_secs` and updates the allocator.
pub async fn run_periodic_sync(
    clients: Arc<std::collections::HashMap<u16, Arc<dyn PrivateExchangeClient>>>,
    http: reqwest::Client,
    allocator: Arc<LocalCapitalAllocator>,
    token_id: usize,
    interval_secs: u64,
) {
    let mut ticker = tokio::time::interval(Duration::from_secs(interval_secs));
    let mut cycle: u64 = 0;

    loop {
        ticker.tick().await;
        cycle += 1;

        let mut total = Decimal::ZERO;
        for (&exchange_id, client) in clients.iter() {
            match sync_exchange_balance(
                client.as_ref(),
                &http,
                exchange_id,
                allocator.as_ref(),
                token_id,
            ).await {
                Ok(bal) => {
                    total += bal;
                }
                Err(e) => {
                    error!(
                        exchange = exchange_id,
                        cycle,
                        error = %e,
                        "periodic balance sync FAILED"
                    );
                }
            }
        }

        if cycle % 10 == 0 {
            info!(
                cycle,
                total_usdt = %total,
                "periodic balance sync"
            );
        }
    }
}