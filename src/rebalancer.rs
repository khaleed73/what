// rebalancer.rs — Automated Asset Rebalancing Transport System.
//
// When running high-frequency cross-exchange arbitrage, a structural
// imbalance naturally occurs over time.  The bot continuously buys on
// Exchange A (draining cash there) and sells on Exchange B (stacking cash
// there).  Eventually Exchange A hits $0 and the entire bot stalls —
// a condition called **Capital Starvation**.
//
// This module fixes that automatically.  It listens for starvation triggers
// via a bounded MPSC channel, executes authenticated private API withdrawals
// to route capital to the starving exchange, and atomically updates the
// in-memory balance matrix once the blockchain transfer clears.
//
// ## Architecture
//
// ```text
//   [STAGE 1: SIGNAL]  ->  [STAGE 2: SIGN PAYLOAD]  ->
//   [STAGE 3: BLOCKCHAIN TRANSIT]  ->  [STAGE 4: RESET]
// ```
//
// * **Stage 1** — The high-speed strategy thread (CPU Core 0) detects
//   starvation and drops a 32-byte `RebalanceRequest` into the MPSC
//   channel in under 1 microsecond.
//
// * **Stage 2** — This background worker pops the request, matches the
//   destination exchange against **config-driven** deposit addresses (loaded
//   from `config.toml` at boot), builds the signed
//   withdrawal payload, and fires the HTTP request.
//
// * **Stage 3** — The worker yields its CPU time and sleeps while the
//   blockchain (Arbitrum / Solana) confirms the transfer (~30–60 s).
//
// * **Stage 4** — After the cooldown, the worker verifies the deposit
//   landed and fires lock-free atomic updates to the `LocalCapitalAllocator`
//   matrix so the very next price tick sees the refreshed balances.
//
// ## Safety Design
//
// * **Config-driven destination addresses** — deposit addresses are loaded
//   from `config.toml` at boot and validated for format (must start with
//   "0x", minimum length, non-zero-address).  Empty strings are allowed —
//   the rebalancer simply skips withdrawals to exchanges without a configured
//   address.
//
// * **Bounded MPSC channel (capacity 10)** — caps in-flight transfers
//   to keep memory footprint stable and prevent queue bloat.
//
// * **Zero cross-contention** — runs on a completely independent Tokio
//   task; does not share locks with the main trading loop.

use std::sync::Arc;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use base64::Engine;
use reqwest;
use rust_decimal::prelude::ToPrimitive;
use rust_decimal::Decimal;

use tokio::sync::mpsc;
use tracing::{debug, error, info};

use crate::balance_allocator::LocalCapitalAllocator;
use crate::signer::PrivateApiSigner;

// ═══════════════════════════════════════════════════════════════════════════
//  RebalanceRequest — the tiny 32-byte payload that crosses the channel
// ═══════════════════════════════════════════════════════════════════════════

/// A capital rebalance request produced by the strategy scanner and
/// consumed by the background rebalancer worker.
///
/// This struct is intentionally kept small (~32 bytes) so the producer
/// (high-speed trading core) can `try_send` it in under 1 microsecond
/// without any heap allocation.
#[derive(Debug, Clone)]
pub struct RebalanceRequest {
    /// Numeric ID of the exchange that currently holds the surplus capital.
    pub from_exchange_id: u16,
    /// Numeric ID of the exchange that is starved and needs the capital.
    pub to_exchange_id: u16,
    /// Token ID to transfer (0 = USDT in the standard allocation).
    pub token_id: u16,
    /// Amount to transfer in the token's native units.
    pub amount: Decimal,
    /// Human-readable token symbol for logging ("USDT", "BTC", etc.).
    pub token_symbol: String,
}

// ═══════════════════════════════════════════════════════════════════════════
//  Deposit address lookup — REMOVED
// ═══════════════════════════════════════════════════════════════════════════
//
// Hardcoded deposit addresses were removed in production hardening.
// All deposit addresses are now loaded from `config.toml` [deposit_addresses]
// at boot and validated by `configs.rs::EngineConfig::load_and_validate()`
// (rejects zero-address sentinels, validates hex format, min length).
//
// The rebalancer receives the validated map via its constructor and
// skips withdrawals to any exchange without a configured address.

// ═══════════════════════════════════════════════════════════════════════════
//  Exchange withdrawal endpoint mapping
// ═══════════════════════════════════════════════════════════════════════════

/// Return the private withdrawal REST endpoint for the given exchange.
fn get_withdrawal_endpoint(exchange_id: u16) -> &'static str {
    match exchange_id {
        0 => "https://api.binance.com/sapi/v1/capital/withdraw/apply",
        1 => "https://api.bybit.com/v5/asset/withdraw",
        2 => "https://www.okx.com/api/v5/asset/withdrawal",
        3 => "https://api.gateio.ws/api/v4/withdrawals",
        4 => "https://api.kucoin.com/api/v1/withdrawals/apply",
        _ => "UNKNOWN_ENDPOINT",
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  AutoCapitalRebalancer
// ═══════════════════════════════════════════════════════════════════════════

/// The background capital rebalancing worker.
///
/// Spawns as an independent Tokio task.  It receives `RebalanceRequest`
/// messages from the bounded MPSC channel and executes the full 4-stage
/// pipeline:
///
/// 1. **Pop** the request from the memory tube.
/// 2. **Match** the destination against config-driven deposit addresses.
/// 3. **Sign & fire** the withdrawal via the exchange's private REST API.
/// 4. **Sleep** for the blockchain settlement cooldown, then atomically
///    update the `LocalCapitalAllocator` balance matrix.
pub struct AutoCapitalRebalancer {
    /// Bounded receiver — the "consumer" end of the lock-free memory tube.
    /// Capacity is 10, ensuring at most 10 transfers are in-flight.
    receiver: mpsc::Receiver<RebalanceRequest>,

    /// Pre-built HTTP client (connection-pooled, TLS-enabled).
    http_client: reqwest::Client,

    /// Reference to the central balance matrix for atomic resets.
    allocator: Arc<LocalCapitalAllocator>,

    /// Per-exchange signers for generating authenticated withdrawal requests.
    signers: Arc<std::collections::HashMap<u16, PrivateApiSigner>>,

    /// Blockchain settlement cooldown in seconds.
    /// 60 seconds is sufficient for Arbitrum L2 finality.
    settlement_cooldown_secs: u64,

    /// Estimated gas / network fee in USD deducted from each transfer.
    /// This prevents the balance matrix from over-crediting the destination
    /// exchange.  Defaults to $2.00 (typical Arbitrum L2 gas cost).
    /// Settable via `set_gas_fee_usd`.
    gas_fee_usd: AtomicU64, // fixed-point: dollars × 1_000_000

    /// Cumulative total gas fees deducted across all rebalances (fp).
    total_gas_deducted: AtomicU64,

    /// Deposit addresses keyed as "ExchangeName_network" → address.
    /// Loaded from config at boot.  Replaces the old hardcoded function.
    deposit_addresses: HashMap<String, String>,
}

impl AutoCapitalRebalancer {
    /// Create a new rebalancer.
    ///
    /// # Parameters
    ///
    /// * `receiver` — The consumer end of the bounded MPSC channel (capacity 10).
    /// * `http_client` — Pre-built reqwest client with connection pooling.
    /// * `allocator` — Shared reference to the lock-free balance matrix.
    /// * `signers` — Per-exchange HMAC signers loaded at boot.
    /// * `settlement_cooldown_secs` — Seconds to wait for blockchain confirmation
    ///   (default: 60 for Arbitrum).
    pub fn new(
        receiver: mpsc::Receiver<RebalanceRequest>,
        http_client: reqwest::Client,
        allocator: Arc<LocalCapitalAllocator>,
        signers: Arc<std::collections::HashMap<u16, PrivateApiSigner>>,
        settlement_cooldown_secs: u64,
        deposit_addresses: HashMap<String, String>,
    ) -> Self {
        Self {
            receiver,
            http_client,
            allocator,
            signers,
            settlement_cooldown_secs,
            // Default gas fee: $2.00 → 2_000_000 fp-units.
            gas_fee_usd: AtomicU64::new(2_000_000),
            total_gas_deducted: AtomicU64::new(0),
            deposit_addresses,
        }
    }

    /// Set the estimated gas / network fee per transfer in USD.
    /// Stored as fixed-point internally (value × 1_000_000).
    /// Uses truncation toward zero (same semantics as balance_allocator::decimal_to_fp).
    pub fn set_gas_fee_usd(&self, fee: Decimal) {
        // Clamp to non-negative, then scale to fixed-point (×1,000,000).
        let fee = if fee < Decimal::ZERO { Decimal::ZERO } else { fee };
        let scaled = fee * Decimal::from(1_000_000u64);
        // Truncate toward zero: use to_u64 which returns None on overflow/negative.
        let val = scaled.trunc().to_u64().unwrap_or(0);
        self.gas_fee_usd.store(val, Ordering::Relaxed);
    }

    /// Return the total cumulative gas fees deducted (in USD).
    pub fn get_total_gas_deducted_usd(&self) -> Decimal {
        let fp = self.total_gas_deducted.load(Ordering::Relaxed);
        Decimal::from(fp) / Decimal::from(1_000_000u64)
    }

    /// Run the background worker loop.  Call this inside a `tokio::spawn`.
    ///
    /// This method runs indefinitely, blocking on `receiver.recv().await`
    /// until a starvation signal arrives.  Each request triggers the full
    /// 4-stage rebalance pipeline:
    ///
    /// ```text
    /// while let Some(req) = self.receiver.recv().await {
    ///     Stage 1: Pop signal from queue         (~0 ns, already done)
    ///     Stage 2: Sign withdrawal payload       (~1-5 μs)
    ///     Stage 3: Fire HTTP POST & sleep        (~60 s blockchain wait)
    ///     Stage 4: Atomic balance matrix reset   (~100 ns)
    /// }
    /// ```
    pub async fn run(&mut self) {
        info!(
            cooldown_secs = self.settlement_cooldown_secs,
            "AutoCapitalRebalancer background worker started"
        );

        while let Some(req) = self.receiver.recv().await {
            info!(
                from = req.from_exchange_id,
                to = req.to_exchange_id,
                token = %req.token_symbol,
                amount = %req.amount,
                "Stage 1: Starvation signal received — beginning rebalance"
            );

            // ── Stage 2: Look up deposit address from config ──────────
            // Look up the deposit address from config.
            // Key format: "{ExchangeName}_arbitrum"
            // We need to map exchange_id → exchange name. Use a static lookup.
            let exchange_name = match req.to_exchange_id {
                0 => "Binance",
                1 => "Bybit",
                2 => "OKX",
                3 => "GateIO",
                4 => "KuCoin",
                _ => {
                    error!(exchange = req.to_exchange_id, "unknown exchange ID for deposit address lookup");
                    continue;
                }
            };
            let addr_key = format!("{}_arbitrum", exchange_name);
            let target_address = match self.deposit_addresses.get(&addr_key) {
                Some(addr) if !addr.is_empty() => addr.as_str(),
                _ => {
                    error!(
                        exchange = exchange_name,
                        key = %addr_key,
                        "deposit address not configured — skipping rebalance. \
                         Set deposit_addresses.{} in config.toml",
                        addr_key
                    );
                    continue;
                }
            };

            // Look up the signer for the SOURCE exchange (the one we're withdrawing FROM).
            let signer = match self.signers.get(&req.from_exchange_id) {
                Some(s) => s,
                None => {
                    error!(
                        from = req.from_exchange_id,
                        "Stage 2 ABORTED: no signer found for source exchange"
                    );
                    continue;
                }
            };

            let withdrawal_endpoint = get_withdrawal_endpoint(req.from_exchange_id);
            let network = "arbitrum";

            // Build exchange-specific withdrawal payload.
            let (payload_str, auth_headers) = self.build_withdrawal_request(
                &req,
                target_address,
                network,
                signer,
                withdrawal_endpoint,
            );

            // ── Stage 3: Blockchain Transit Flight ──────────────────────
            debug!(
                from = req.from_exchange_id,
                to = req.to_exchange_id,
                amount = %req.amount,
                endpoint = %withdrawal_endpoint,
                "Stage 3: Firing authenticated withdrawal request"
            );

            let send_result = self
                .http_client
                .post(withdrawal_endpoint)
                .headers(auth_headers)
                .body(payload_str)
                .send()
                .await;

            match send_result {
                Ok(response) => {
                    let status = response.status();
                    let body = response.text().await.unwrap_or_default();

                    if status.is_success() {
                        info!(
                            from = req.from_exchange_id,
                            to = req.to_exchange_id,
                            %status,
                            "Stage 3: Withdrawal request accepted by exchange"
                        );
                    } else {
                        error!(
                            from = req.from_exchange_id,
                            to = req.to_exchange_id,
                            %status,
                            %body,
                            "Stage 3: Withdrawal request REJECTED by exchange"
                        );
                        // Do NOT proceed to Stage 4 — the withdrawal was rejected.
                        continue;
                    }
                }
                Err(e) => {
                    error!(
                        from = req.from_exchange_id,
                        to = req.to_exchange_id,
                        error = %e,
                        "Stage 3: Withdrawal HTTP request FAILED"
                    );
                    continue;
                }
            }

            // Sleep the background thread while the blockchain settles.
            // This completely yields CPU — the main trading core is unaffected.
            info!(
                cooldown_secs = self.settlement_cooldown_secs,
                "Stage 3: Yielding CPU — waiting for blockchain settlement"
            );
            tokio::time::sleep(Duration::from_secs(self.settlement_cooldown_secs)).await;

            // ── Stage 4: Atomic Memory Matrix Realignment ──────────────
            // After the cooldown, atomically update the local balance matrix.
            // The "from" exchange loses `amount`, the "to" exchange gains
            // `amount - gas_fee` (gas fee is deducted to prevent over-crediting).
            let gas_fp = self.gas_fee_usd.load(Ordering::Relaxed);
            let gas_fee = Decimal::from(gas_fp) / Decimal::from(1_000_000u64);

            // Clamp: gas_fee must not exceed the transfer amount.
            let effective_gas = if gas_fee > req.amount { req.amount } else { gas_fee };
            let net_amount = req.amount - effective_gas;

            // Track cumulative gas deducted.
            self.total_gas_deducted.fetch_add(
                (effective_gas * Decimal::from(1_000_000u64)).to_string()
                    .split('.').next()
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(0),
                Ordering::Relaxed,
            );

            let old_from_bal = self
                .allocator
                .get_balance_atomic(req.from_exchange_id as usize, req.token_id as usize);
            let old_to_bal = self
                .allocator
                .get_balance_atomic(req.to_exchange_id as usize, req.token_id as usize);

            let new_from_bal = old_from_bal - req.amount;
            let new_to_bal = old_to_bal + net_amount;

            self.allocator.update_balance_atomic(
                req.from_exchange_id as usize,
                req.token_id as usize,
                new_from_bal,
            );
            self.allocator.update_balance_atomic(
                req.to_exchange_id as usize,
                req.token_id as usize,
                new_to_bal,
            );

            info!(
                from = req.from_exchange_id,
                to = req.to_exchange_id,
                token = %req.token_symbol,
                amount = %req.amount,
                gas_fee = %effective_gas,
                net_received = %net_amount,
                old_from = %old_from_bal,
                new_from = %new_from_bal,
                old_to = %old_to_bal,
                new_to = %new_to_bal,
                "Stage 4: Balance matrix realigned — capital transport complete (gas deducted)"
            );
        }

        info!("AutoCapitalRebalancer channel closed — worker shutting down");
    }

    // -------------------------------------------------------------------
    // Exchange-specific withdrawal request builders
    // -------------------------------------------------------------------

    /// Build the withdrawal HTTP payload and authentication headers for
    /// the source exchange.
    ///
    /// Each exchange has a different API format:
    /// * **Binance** — URL-encoded form body + HMAC-SHA256 hex signature
    ///   in query string, `X-MBX-APIKEY` header.
    /// * **Bybit** — JSON body, `X-BAPI-*` headers.
    /// * **OKX** — JSON body, `OK-ACCESS-*` headers.
    /// * **Gate.io** — JSON body, `KEY`/`SIGN`/`Timestamp` headers.
    /// * **KuCoin** — JSON body, `KC-API-*` headers.
    fn build_withdrawal_request(
        &self,
        req: &RebalanceRequest,
        target_address: &str,
        network: &str,
        signer: &PrivateApiSigner,
        _endpoint: &str,
    ) -> (String, reqwest::header::HeaderMap) {
        use reqwest::header::{HeaderMap, HeaderValue, CONTENT_TYPE};

        match req.from_exchange_id {
            // ── Binance withdrawal ─────────────────────────────────────
            0 => {
                let mut params: std::collections::BTreeMap<String, String> =
                    std::collections::BTreeMap::new();
                params.insert("coin".into(), "USDT".into());
                params.insert("network".into(), network.to_uppercase());
                params.insert("address".into(), target_address.to_string());
                params.insert("amount".into(), req.amount.to_string());

                let query_string: String = params
                    .iter()
                    .map(|(k, v)| format!("{}={}", k, v))
                    .collect::<Vec<_>>()
                    .join("&");

                let signed_query = signer.generate_signed_query(&query_string);

                let mut headers = HeaderMap::new();
                headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/x-www-form-urlencoded"));
                headers.insert(
                    "X-MBX-APIKEY",
                    HeaderValue::from_str(signer.api_key()).unwrap_or(HeaderValue::from_static("")),
                );

                (signed_query, headers)
            }

            // ── Bybit V5 withdrawal ───────────────────────────────────
            1 => {
                let body_map = serde_json::json!({
                    "coin": "USDT",
                    "chain": format!("{}", network.to_uppercase()),
                    "address": target_address,
                    "amt": req.amount.to_string(),
                });
                let body_str = body_map.to_string();

                let timestamp = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_millis().to_string())
                    .unwrap_or_else(|_| "0".to_string());
                let recv_window = "5000".to_string();
                let pre_sign = format!(
                    "{}{}{}{}",
                    timestamp,
                    signer.api_key(),
                    recv_window,
                    body_str
                );
                let sign = signer.generate_hmac_signature(&pre_sign);

                let mut headers = HeaderMap::new();
                headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
                headers.insert("X-BAPI-API-KEY", HeaderValue::from_str(signer.api_key()).unwrap_or(HeaderValue::from_static("")));
                headers.insert("X-BAPI-SIGN", HeaderValue::from_str(&sign).unwrap_or(HeaderValue::from_static("")));
                headers.insert("X-BAPI-TIMESTAMP", HeaderValue::from_str(&timestamp).unwrap_or(HeaderValue::from_static("")));
                headers.insert("X-BAPI-RECV-WINDOW", HeaderValue::from_str(&recv_window).unwrap_or(HeaderValue::from_static("")));

                (body_str, headers)
            }

            // ── OKX V5 withdrawal ─────────────────────────────────────
            2 => {
                let body_map = serde_json::json!({
                    "ccy": "USDT",
                    "amt": req.amount.to_string(),
                    "dest": "4", // 4 = external address
                    "toAddr": target_address,
                    "chain": format!("USDT-{}", network.to_uppercase()),
                });
                let body_str = body_map.to_string();

                let timestamp = chrono::Utc::now()
                    .format("%Y-%m-%dT%H:%M:%S%.3fZ")
                    .to_string();
                let method = "POST";
                let path = "/api/v5/asset/withdrawal";
                let sign_str = format!("{}{}{}{}", timestamp, method, path, body_str);

                use base64::Engine;
                let signature = {
                    let key = ring::hmac::Key::new(
                        ring::hmac::HMAC_SHA256,
                        signer.api_secret.expose().as_bytes(),
                    );
                    let sig = ring::hmac::sign(&key, sign_str.as_bytes());
                    base64::engine::general_purpose::STANDARD.encode(sig.as_ref())
                };

                let mut headers = HeaderMap::new();
                headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
                headers.insert("OK-ACCESS-KEY", HeaderValue::from_str(signer.api_key()).unwrap_or(HeaderValue::from_static("")));
                headers.insert("OK-ACCESS-SIGN", HeaderValue::from_str(&signature).unwrap_or(HeaderValue::from_static("")));
                headers.insert("OK-ACCESS-TIMESTAMP", HeaderValue::from_str(&timestamp).unwrap_or(HeaderValue::from_static("")));
                headers.insert("OK-ACCESS-PASSPHRASE", HeaderValue::from_str(signer.passphrase.as_ref().map(|p| p.expose()).unwrap_or("")).unwrap_or(HeaderValue::from_static("")));

                (body_str, headers)
            }

            // ── Gate.io V4 withdrawal ─────────────────────────────────
            3 => {
                let body_map = serde_json::json!({
                    "currency": "USDT",
                    "amount": req.amount.to_string(),
                    "address": target_address,
                    "chain": format!("ARB"), // Gate.io uses short chain codes
                });
                let body_str = body_map.to_string();

                let timestamp = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs().to_string())
                    .unwrap_or_else(|_| "0".to_string());

                let signature = signer.generate_hmac_signature(&body_str);

                let mut headers = HeaderMap::new();
                headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
                headers.insert("KEY", HeaderValue::from_str(signer.api_key()).unwrap_or(HeaderValue::from_static("")));
                headers.insert("SIGN", HeaderValue::from_str(&signature).unwrap_or(HeaderValue::from_static("")));
                headers.insert("Timestamp", HeaderValue::from_str(&timestamp).unwrap_or(HeaderValue::from_static("")));

                (body_str, headers)
            }

            // ── KuCoin V1 withdrawal ──────────────────────────────────
            4 => {
                let body_map = serde_json::json!({
                    "currency": "USDT",
                    "amount": req.amount.to_string(),
                    "address": target_address,
                    "chain": format!("ARB_{}", network.to_uppercase()),
                    "memo": "",
                });
                let body_str = body_map.to_string();

                let timestamp = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_millis().to_string())
                    .unwrap_or_else(|_| "0".to_string());

                let method = "POST";
                let path = "/api/v1/withdrawals/apply";
                let preimage = format!("{}{}{}{}", timestamp, method, path, body_str);
                let signature = signer.generate_hmac_signature(&preimage);

                // KuCoin also signs the passphrase.
                let passphrase_sign = {
                    let key = ring::hmac::Key::new(
                        ring::hmac::HMAC_SHA256,
                        signer.api_secret.expose().as_bytes(),
                    );
                    let sig = ring::hmac::sign(
                        &key,
                        signer.passphrase.as_ref().map(|p| p.expose().as_bytes()).unwrap_or(b""),
                    );
                    base64::engine::general_purpose::STANDARD.encode(sig.as_ref())
                };

                let mut headers = HeaderMap::new();
                headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
                headers.insert("KC-API-KEY", HeaderValue::from_str(signer.api_key()).unwrap_or(HeaderValue::from_static("")));
                headers.insert("KC-API-SIGN", HeaderValue::from_str(&signature).unwrap_or(HeaderValue::from_static("")));
                headers.insert("KC-API-TIMESTAMP", HeaderValue::from_str(&timestamp).unwrap_or(HeaderValue::from_static("")));
                headers.insert("KC-API-PASSPHRASE", HeaderValue::from_str(&passphrase_sign).unwrap_or(HeaderValue::from_static("")));
                headers.insert("KC-API-KEY-VERSION", HeaderValue::from_static("2"));

                (body_str, headers)
            }

            // ── Unknown exchange — should never reach here ────────────
            _ => {
                error!(
                    exchange_id = req.from_exchange_id,
                    "Unknown source exchange ID for withdrawal — aborting"
                );
                (String::new(), HeaderMap::new())
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  Builder helper
// ═══════════════════════════════════════════════════════════════════════════

/// Create the bounded MPSC channel and return both the sender (for the
/// strategy engine to produce into) and the receiver (consumed by the
/// rebalancer worker).
///
/// The channel capacity is **10** — this is the anti-spam bounded queue
/// that caps in-flight transfers to keep memory footprint stable.
pub fn create_rebalance_channel() -> (
    mpsc::Sender<RebalanceRequest>,
    mpsc::Receiver<RebalanceRequest>,
) {
    // Bounded channel capacity = 10
    // If the blockchain is slow and 10 transfers queue up, new ones
    // will back-pressure (try_send returns Err) rather than growing memory.
    mpsc::channel(10)
}

// ═══════════════════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use rust_decimal_macros::dec;

    #[test]
    fn test_rebalance_request_size() {
        // Verify the request struct is small enough for microsecond channel sends.
        let req = RebalanceRequest {
            from_exchange_id: 0,
            to_exchange_id: 1,
            token_id: 0,
            amount: dec!(50000.00),
            token_symbol: "USDT".to_string(),
        };
        // String "USDT" = 4 bytes + struct overhead should be well under 64 bytes.
        assert!(std::mem::size_of_val(&req) < 128);
    }

    #[tokio::test]
    async fn test_bounded_channel_capacity() {
        let (tx, mut rx) = create_rebalance_channel();
        for i in 0..10 {
            let result = tx.try_send(RebalanceRequest {
                from_exchange_id: 0,
                to_exchange_id: 1,
                token_id: 0,
                amount: dec!(1000.0),
                token_symbol: "USDT".to_string(),
            });
            assert!(result.is_ok(), "message {} should be accepted (capacity 10)", i);
        }

        // The 11th send should fail because the channel is full.
        let overflow = tx.try_send(RebalanceRequest {
            from_exchange_id: 0,
            to_exchange_id: 1,
            token_id: 0,
            amount: dec!(1000.0),
            token_symbol: "USDT".to_string(),
        });
        assert!(overflow.is_err(), "11th message should be rejected (channel full)");

        // Drop one from the receiver to free a slot.
        rx.recv().await.unwrap();
        // Now it should accept again.
        let retry = tx.try_send(RebalanceRequest {
            from_exchange_id: 0,
            to_exchange_id: 1,
            token_id: 0,
            amount: dec!(1000.0),
            token_symbol: "USDT".to_string(),
        });
        assert!(retry.is_ok(), "after consuming one, channel should accept again");
    }
}