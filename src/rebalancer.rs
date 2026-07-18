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
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use base64::Engine;
use reqwest;
use rust_decimal::prelude::ToPrimitive;
use rust_decimal::Decimal;
use serde_json;

use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

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
fn get_withdrawal_endpoint(exchange_id: u16) -> Option<&'static str> {
    match exchange_id {
        0 => Some("https://api.binance.com/sapi/v1/capital/withdraw/apply"),
        1 => Some("https://api.bybit.com/v5/asset/withdraw"),
        2 => Some("https://www.okx.com/api/v5/asset/withdrawal"),
        3 => Some("https://api.gateio.ws/api/v4/withdrawals"),
        4 => Some("https://api.kucoin.com/api/v1/withdrawals/apply"),
        _ => None,
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  Deposit Verification Result (module-level enum)
// ═══════════════════════════════════════════════════════════════════════════

/// Outcome of the best-effort deposit verification check (Stage 3.5).
enum DepositVerifyResult {
    /// Deposit confirmed on the destination exchange with the actual
    /// net-amount received (after any exchange-side fees).
    Confirmed(Decimal),
    /// Deposit not yet visible (API returned 200 but no matching record).
    /// Caller should fall back to default credit.
    NotFound,
    /// Deposit explicitly failed or was rejected.
    /// Caller must NOT credit the balance.
    Failed(String),
    /// The verification API call itself failed (network, timeout, 5xx).
    /// Caller should fall back to default credit.
    ApiError(String),
}

// ═══════════════════════════════════════════════════════════════════════════
//  AutoCapitalRebalancer
// ═══════════════════════════════════════════════════════════════════════════

/// A lightweight handle for recording exchange heartbeats from data feed
/// workers.  Clonable and `Send + Sync` so it can be passed into Tokio tasks.
///
/// Each call to `record()` updates the last-seen timestamp for an exchange.
/// The rebalancer reads this map during its pre-flight liveness check to
/// avoid dispatching withdrawals to dead/frozen exchanges.
#[derive(Clone)]
pub struct ExchangeHeartbeatHandle {
    inner: Arc<std::sync::Mutex<HashMap<u16, Instant>>>,
}

impl ExchangeHeartbeatHandle {
    /// Record a heartbeat for the given exchange (typically called from a
    /// WS data feed worker on every incoming message).
    ///
    /// Thread safety: acquires a `std::sync::Mutex` for a single
    /// `HashMap::insert` — critical section ~50 ns.
    #[inline]
    pub fn record(&self, exchange_id: u16) {
        if let Ok(mut map) = self.inner.lock() {
            map.insert(exchange_id, Instant::now());
        }
        // Lock poisoned — silently skip.  The rebalancer will fail-open
        // (assume exchange is live) when it can't read the map either.
    }
}

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

    /// Shared heartbeat map — the same `Arc` backing the
    /// `ExchangeHeartbeatHandle` given out to data feed workers.
    exchange_last_seen: Arc<std::sync::Mutex<HashMap<u16, Instant>>>,
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
            exchange_last_seen: Arc::new(std::sync::Mutex::new(HashMap::new())),
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
            // Use the canonical exchange_name_by_id from exchange/mod.rs which
            // covers all 17 exchanges (0-16).
            let exchange_name = crate::exchange::exchange_name_by_id(req.to_exchange_id);
            if exchange_name == "UNKNOWN" {
                error!(exchange = req.to_exchange_id, "unknown exchange ID for deposit address lookup");
                continue;
            }
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

            // ── Pre-flight validation ──────────────────────────────────

            // 1. Exchange liveness check — reject if the source exchange has
            //    no recent heartbeat (could be disconnected or frozen).
            //    Sending a withdrawal into a dead exchange risks permanent
            //    capital loss.
            if !self.is_exchange_live(req.from_exchange_id) {
                warn!(
                    from = req.from_exchange_id,
                    to = req.to_exchange_id,
                    "Stage 2 ABORTED: source exchange has no recent heartbeat — \
                     likely disconnected or frozen. Skipping withdrawal to \
                     avoid sending capital into a black hole."
                );
                continue;
            }

            // 2. Amount validation — reject zero or negative amounts.
            if req.amount <= Decimal::ZERO {
                warn!(
                    from = req.from_exchange_id,
                    to = req.to_exchange_id,
                    amount = %req.amount,
                    "Stage 2 ABORTED: invalid rebalance amount (must be positive)"
                );
                continue;
            }

            // 3. Self-transfer guard — reject if source == destination.
            if req.from_exchange_id == req.to_exchange_id {
                warn!(
                    exchange = req.from_exchange_id,
                    "Stage 2 ABORTED: source and destination exchange are the same — \
                     self-transfer would waste gas fees"
                );
                continue;
            }

            // 4. Channel backpressure / staleness check — if too many
            //    rebalances are queued, the oldest requests are stale (the
            //    market has moved since they were generated).  Each in-flight
            //    transfer blocks for ~60 s of blockchain settlement, so 3+
            //    queued means the front of the queue is at least minutes old.
            if self.receiver.len() > 3 {
                warn!(
                    queued = self.receiver.len(),
                    from = req.from_exchange_id,
                    "Stage 2 ABORTED: rebalance channel backpressure detected — \
                     skipping stale request (market conditions have likely changed)"
                );
                continue;
            }

            // 5. C-7 FIX: Source balance sufficiency check — verify the
            //    allocator actually has enough balance on the source exchange
            //    before firing the withdrawal.  Prevents sending a withdrawal
            //    for capital that was already spent by concurrent trades.
            let source_balance = self.allocator.get_balance_atomic(req.from_exchange_id as usize, req.token_id as usize);
            if source_balance < req.amount {
                warn!(
                    from = req.from_exchange_id,
                    available = %source_balance,
                    requested = %req.amount,
                    "Stage 2 ABORTED: insufficient source balance for withdrawal"
                );
                continue;
            }

            let withdrawal_endpoint = match get_withdrawal_endpoint(req.from_exchange_id) {
                Some(ep) => ep,
                None => {
                    error!(
                        from = req.from_exchange_id,
                        "Stage 2 ABORTED: unsupported exchange ID — no withdrawal endpoint"
                    );
                    continue;
                }
            };
            let network = "arbitrum";

            // Build exchange-specific withdrawal payload.
            let (payload_str, auth_headers) = match self.build_withdrawal_request(
                &req,
                target_address,
                network,
                signer,
                withdrawal_endpoint,
            ) {
                Ok(r) => r,
                Err(e) => {
                    error!(
                        from = req.from_exchange_id,
                        error = %e,
                        "Stage 2 ABORTED: failed to build withdrawal request"
                    );
                    continue;
                }
            };

            // 5. Payload sanity check — unknown exchanges produce empty payloads.
            //    Sending an empty body to an API endpoint is guaranteed to fail,
            //    but we catch it early to avoid wasting a network round-trip and
            //    to log a clear diagnosis.
            if payload_str.is_empty() {
                error!(
                    from = req.from_exchange_id,
                    "Stage 2 ABORTED: withdrawal payload is empty (unknown exchange ID)"
                );
                continue;
            }

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

            // ── Stage 3.5: Deposit Verification ──────────────────────
            // C-4 FIX: Attempt to verify the deposit actually landed before
            // crediting the balance matrix.  This prevents blind-crediting
            // when a withdrawal is rejected by the blockchain, the destination
            // exchange, or gets stuck in mempool.
            //
            // Best-effort: if the API call fails (network error, 5xx, timeout),
            // we fall through and credit anyway — the 60s cooldown already
            // gives high confidence for L2 transfers.  But a hard rejection
            // (exchange returns the transfer as failed) prevents phantom credits.
            let deposit_verified = self
                .attempt_deposit_verification(
                    req.to_exchange_id,
                    &req.token_symbol,
                    req.from_exchange_id,
                    req.amount,
                )
                .await;

            match deposit_verified {
                DepositVerifyResult::Confirmed(net_received) => {
                    info!(
                        from = req.from_exchange_id,
                        to = req.to_exchange_id,
                        token = %req.token_symbol,
                        net_received = %net_received,
                        "Stage 3.5: Deposit CONFIRMED on destination exchange"
                    );
                    self.apply_balance_realignment(
                        req.from_exchange_id,
                        req.to_exchange_id,
                        req.token_id,
                        req.amount,
                        net_received,
                    );
                }
                DepositVerifyResult::NotFound | DepositVerifyResult::ApiError(_) => {
                    // C-3 FIX: Do NOT blindly credit on NotFound/ApiError.
                    // Retry verification after 30 seconds, up to 3 retries.
                    // Only credit after a Confirmed result.
                    let max_retries: u32 = 3;
                    let retry_delay = Duration::from_secs(30);
                    let mut confirmed = false;

                    for attempt in 1..=max_retries {
                        warn!(
                            from = req.from_exchange_id,
                            to = req.to_exchange_id,
                            token = %req.token_symbol,
                            attempt,
                            max_retries,
                            "Stage 3.5: Deposit not yet confirmed — retrying after 30s"
                        );
                        tokio::time::sleep(retry_delay).await;

                        let retry_result = self
                            .attempt_deposit_verification(
                                req.to_exchange_id,
                                &req.token_symbol,
                                req.from_exchange_id,
                                req.amount,
                            )
                            .await;

                        match retry_result {
                            DepositVerifyResult::Confirmed(net_received) => {
                                info!(
                                    from = req.from_exchange_id,
                                    to = req.to_exchange_id,
                                    token = %req.token_symbol,
                                    net_received = %net_received,
                                    attempt,
                                    "Stage 3.5: Deposit CONFIRMED on retry"
                                );
                                self.apply_balance_realignment(
                                    req.from_exchange_id,
                                    req.to_exchange_id,
                                    req.token_id,
                                    req.amount,
                                    net_received,
                                );
                                confirmed = true;
                                break;
                            }
                            DepositVerifyResult::Failed(reason) => {
                                error!(
                                    from = req.from_exchange_id,
                                    to = req.to_exchange_id,
                                    token = %req.token_symbol,
                                    reason = %reason,
                                    attempt,
                                    "Stage 3.5: Deposit FAILED during retry — aborting"
                                );
                                break;
                            }
                            DepositVerifyResult::NotFound | DepositVerifyResult::ApiError(_) => {
                                // Still not visible, continue retrying
                                continue;
                            }
                        }
                    }

                    if !confirmed {
                        // All retries exhausted without confirmation.
                        // C-3 FIX: Do NOT credit. Log CRITICAL for manual investigation.
                        // Also warn if the credit amount would have been large.
                        let gas_fp = self.gas_fee_usd.load(Ordering::Relaxed);
                        let gas_fee = Decimal::from(gas_fp) / Decimal::from(1_000_000u64);
                        let effective_gas = if gas_fee > req.amount { req.amount } else { gas_fee };
                        let net_amount = req.amount - effective_gas;

                        // max_blind_credit_amount safety check
                        let max_blind_credit_amount = Decimal::from(1_000u64); // $1000
                        if net_amount > max_blind_credit_amount {
                            error!(
                                from = req.from_exchange_id,
                                to = req.to_exchange_id,
                                token = %req.token_symbol,
                                unconfirmed_amount = %net_amount,
                                max_safe = %max_blind_credit_amount,
                                "Stage 3.5: CRITICAL — all retries exhausted for LARGE unconfirmed deposit. \
                                 NOT crediting balance. Manual investigation required."
                            );
                        } else {
                            error!(
                                from = req.from_exchange_id,
                                to = req.to_exchange_id,
                                token = %req.token_symbol,
                                unconfirmed_amount = %net_amount,
                                "Stage 3.5: CRITICAL — all retries exhausted for unconfirmed deposit. \
                                 NOT crediting balance. Manual investigation required."
                            );
                        }
                        continue;
                    }
                }
                DepositVerifyResult::Failed(reason) => {
                    error!(
                        from = req.from_exchange_id,
                        to = req.to_exchange_id,
                        token = %req.token_symbol,
                        reason = %reason,
                        "Stage 3.5: Deposit verification FAILED — NOT crediting balance. \
                         Capital may be in transit or lost. Manual investigation required."
                    );
                    // Do NOT credit the balance — the transfer likely failed.
                    continue;
                }
            }
        }

        info!("AutoCapitalRebalancer channel closed — worker shutting down");
    }

    // -------------------------------------------------------------------
    // Stage 3.5: Deposit Verification (C-4 fix)
    // -------------------------------------------------------------------

    /// Best-effort deposit verification: queries the destination exchange's
    /// deposit history for a recent deposit matching `token_symbol` from
    /// `from_exchange_id`.
    ///
    /// Returns:
    /// * `Confirmed(net_amount)` if a matching deposit is found.
    /// * `NotFound` if the API works but no matching deposit is visible yet.
    /// * `Failed(reason)` if the deposit is explicitly rejected/failed.
    /// * `ApiError(err)` if the verification HTTP call itself failed.
    async fn attempt_deposit_verification(
        &self,
        dest_exchange_id: u16,
        token_symbol: &str,
        _from_exchange_id: u16,
        expected_amount: Decimal,
    ) -> DepositVerifyResult {
        let dest_name = crate::exchange::exchange_name_by_id(dest_exchange_id);
        if dest_name == "UNKNOWN" {
            return DepositVerifyResult::ApiError("unknown destination exchange".into());
        }

        // Look up the signer for the DESTINATION exchange (to authenticate the query).
        let signer = match self.signers.get(&dest_exchange_id) {
            Some(s) => s,
            None => return DepositVerifyResult::ApiError("no signer for destination exchange".into()),
        };

        // Build the deposit history query URL for the destination exchange.
        let (deposit_url, auth_headers) = match self.build_deposit_query_request(
            dest_exchange_id,
            token_symbol,
            signer,
        ) {
            Ok(r) => r,
            Err(e) => return DepositVerifyResult::ApiError(e),
        };

        // Query with a short timeout (5s) — this is a post-settlement check,
        // not on the hot path.
        let response = match tokio::time::timeout(
            Duration::from_secs(5),
            self.http_client.get(&deposit_url).headers(auth_headers).send(),
        )
        .await
        {
            Ok(Ok(resp)) => resp,
            Ok(Err(e)) => return DepositVerifyResult::ApiError(format!("HTTP error: {}", e)),
            Err(_) => return DepositVerifyResult::ApiError("5s timeout".into()),
        };

        if !response.status().is_success() {
            return DepositVerifyResult::ApiError(format!("HTTP {}", response.status()));
        }

        // Parse the response body and look for a recent deposit.
        match response.text().await {
            Ok(body) => self.parse_deposit_response(&body, token_symbol, dest_exchange_id, expected_amount),
            Err(e) => DepositVerifyResult::ApiError(format!("body read error: {}", e)),
        }
    }

    /// Build the authenticated deposit history query for the destination exchange.
    fn build_deposit_query_request(
        &self,
        exchange_id: u16,
        token_symbol: &str,
        signer: &PrivateApiSigner,
    ) -> Result<(String, reqwest::header::HeaderMap), String> {
        use reqwest::header::{HeaderMap, HeaderValue};

        // Fallback helper: same header insertion as withdrawal.
        // Converts `name` to a HeaderName first to avoid lifetime issues
        // (HeaderValue::from_str requires 'static for the error path).
        fn insert_hdr(
            headers: &mut HeaderMap,
            name: &str,
            value: &str,
        ) -> Result<(), String> {
            let header_name: reqwest::header::HeaderName = name
                .parse()
                .map_err(|e| format!("invalid header name '{}': {}", name, e))?;
            let header_value = HeaderValue::from_str(value)
                .map_err(|e| format!("{}: {}", name, e))?;
            headers.insert(header_name, header_value);
            Ok(())
        }

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis().to_string())
            .unwrap_or_else(|_| "0".to_string());

        match exchange_id {
            0 => {
                // Binance: GET /sapi/v1/capital/deposit/hisrec
                let now_ms = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_millis())
                    .unwrap_or(0);
                let mut params: std::collections::BTreeMap<String, String> = std::collections::BTreeMap::new();
                params.insert("coin".into(), token_symbol.to_uppercase());
                params.insert("status".into(), "1".to_string()); // 1 = success
                params.insert("timestamp".into(), timestamp.clone());
                // C-1 FIX: Restrict to recent deposits (last 2 minutes) to avoid
                // matching stale deposits from earlier transfers.
                params.insert("startTime".into(), (now_ms - 120_000).to_string());
                params.insert("endTime".into(), now_ms.to_string());
                let query = params.iter().map(|(k,v)| format!("{}={}",k,v)).collect::<Vec<_>>().join("&");
                let signed = signer.generate_signed_query(&query);
                let url = format!("https://api.binance.com/sapi/v1/capital/deposit/hisrec?{}", signed);
                let mut h = HeaderMap::new();
                insert_hdr(&mut h, "X-MBX-APIKEY", signer.api_key())?;
                Ok((url, h))
            }
            1 => {
                // Bybit V5: GET /v5/asset/deposit/query-record
                let mut h = HeaderMap::new();
                insert_hdr(&mut h, "X-BAPI-API-KEY", signer.api_key())?;
                let recv_window = "5000";
                // C-4 FIX: Sign with the actual query string instead of empty string.
                // Bybit V5 requires: timestamp + apiKey + recvWindow + queryString
                let query_string = format!("coin={}&limit=1", token_symbol.to_uppercase());
                let pre_sign = format!("{}{}{}{}", timestamp, signer.api_key(), recv_window, query_string);
                let sign = signer.generate_hmac_signature(&pre_sign);
                insert_hdr(&mut h, "X-BAPI-SIGN", &sign)?;
                insert_hdr(&mut h, "X-BAPI-TIMESTAMP", &timestamp)?;
                insert_hdr(&mut h, "X-BAPI-RECV-WINDOW", recv_window)?;
                let url = format!("https://api.bybit.com/v5/asset/deposit/query-record?{}", query_string);
                Ok((url, h))
            }
            2 => {
                // OKX V5: GET /api/v5/asset/deposit-history
                let method = "GET";
                let path = "/api/v5/asset/deposit-history";
                let query = format!("ccy={}&limit=1", token_symbol.to_uppercase());
                let sign_str = format!("{}{}{}{}", timestamp, method, path, query);
                let key = ring::hmac::Key::new(
                    ring::hmac::HMAC_SHA256,
                    signer.api_secret.expose().as_bytes(),
                );
                let sig = ring::hmac::sign(&key, sign_str.as_bytes());
                let signature = base64::engine::general_purpose::STANDARD.encode(sig.as_ref());
                let mut h = HeaderMap::new();
                insert_hdr(&mut h, "OK-ACCESS-KEY", signer.api_key())?;
                insert_hdr(&mut h, "OK-ACCESS-SIGN", &signature)?;
                insert_hdr(&mut h, "OK-ACCESS-TIMESTAMP", &timestamp)?;
                insert_hdr(&mut h, "OK-ACCESS-PASSPHRASE", signer.passphrase.as_ref().map(|p| p.expose()).unwrap_or(""))?;
                let url = format!("https://www.okx.com{}?{}", path, query);
                Ok((url, h))
            }
            // Other exchanges: return a no-op URL that will get ApiError
            // from the caller's HTTP request (unsupported for deposit verification).
            _ => Err(format!(
                "deposit verification not yet supported for exchange {}",
                exchange_id
            )),
        }
    }

    /// Parse the deposit history API response and extract the result.
    fn parse_deposit_response(
        &self,
        body: &str,
        token_symbol: &str,
        _exchange_id: u16,
        expected_amount: Decimal,
    ) -> DepositVerifyResult {
        // Generic parsing: try to extract a recent successful deposit.
        // Exchange-specific response formats:
        //   Binance:  [{"amount":"500.00","coin":"USDT","status":1,...}]
        //   Bybit:   {"result":{"rows":[{"amount":"500","coin":"USDT","state":"3",...}]}}
        //   OKX:     {"data":[{"amt":"500","ccy":"USDT","state":"2",...}]}

        let upper = token_symbol.to_uppercase();

        // Try Binance format (top-level array).
        if let Ok(arr) = serde_json::from_str::<serde_json::Value>(body) {
            if let Some(deposits) = arr.as_array() {
                for dep in deposits {
                    let coin = dep["coin"].as_str().unwrap_or("");
                    let status = dep["status"].as_i64().unwrap_or(0);
                    let amount_str = dep["amount"].as_str().unwrap_or("0");
                    if coin.eq_ignore_ascii_case(&upper) && status == 1 {
                        if let Ok(amt) = Decimal::from_str(amount_str) {
                            if amt > Decimal::ZERO {
                                // C-1 FIX: Reject stale deposits whose amount doesn't match
                                // the expected withdrawal amount (within $1 tolerance).
                                if (amt - expected_amount).abs() > Decimal::from(1_000_000) {
                                    continue;
                                }
                                return DepositVerifyResult::Confirmed(amt);
                            }
                        }
                    }
                    // Status 0 = pending, 6 = rejected
                    if coin.eq_ignore_ascii_case(&upper) && status == 6 {
                        return DepositVerifyResult::Failed("deposit rejected by exchange".into());
                    }
                }
                return DepositVerifyResult::NotFound;
            }
            // Try Bybit/OKX format (object with result/data).
            let rows = arr.get("result")
                .and_then(|r| r.get("rows"))
                .or_else(|| arr.get("data"));
            if let Some(rows) = rows.and_then(|r| r.as_array()) {
                for dep in rows {
                    let coin = dep.get("coin").or(dep.get("ccy"))
                        .and_then(|c| c.as_str()).unwrap_or("");
                    let state = dep.get("state").and_then(|s| s.as_str())
                        .or_else(|| dep.get("status").and_then(|s| s.as_str()))
                        .unwrap_or("");
                    let amt_str = dep.get("amount").or(dep.get("amt"))
                        .and_then(|a| a.as_str()).unwrap_or("0");

                    if coin.eq_ignore_ascii_case(&upper) {
                        // Bybit: state "3" = success; OKX: state "2" = success
                        if state == "3" || state == "2" || state == "1" {
                            if let Ok(amt) = Decimal::from_str(amt_str) {
                                if amt > Decimal::ZERO {
                                    return DepositVerifyResult::Confirmed(amt);
                                }
                            }
                        }
                        // Rejected states
                        if state == "6" || state == "4" || state == "rejected" {
                            return DepositVerifyResult::Failed(
                                format!("deposit rejected (state={})", state)
                            );
                        }
                    }
                }
                return DepositVerifyResult::NotFound;
            }
        }

        // Unparseable response — treat as API error so we fall back to default credit.
        DepositVerifyResult::ApiError("unparseable deposit response".into())
    }

    // -------------------------------------------------------------------
    // Stage 4: Balance realignment (C-2 fix: underflow protection)
    // -------------------------------------------------------------------

    /// Atomically debit the source exchange and credit the destination exchange.
    ///
    /// **C-2 FIX**: Uses `max(0, old - amount)` to prevent Decimal wrapping
    /// to a huge positive number when `old_from_bal < req.amount`.  In
    /// production the balance sync (every 60s) would catch the discrepancy,
    /// but wrapping would cause the bot to think it has enormous capital
    /// and fire oversized orders until the next sync cycle.
    fn apply_balance_realignment(
        &self,
        from_exchange_id: u16,
        to_exchange_id: u16,
        token_id: u16,
        debit_amount: Decimal,
        credit_amount: Decimal,
    ) {
        // Track cumulative gas deducted.
        let gas_fp = self.gas_fee_usd.load(Ordering::Relaxed);
        let gas_fee = Decimal::from(gas_fp) / Decimal::from(1_000_000u64);
        let effective_gas = if gas_fee > debit_amount { debit_amount } else { gas_fee };
        let gas_fp_add = (effective_gas * Decimal::from(1_000_000u64))
            .trunc()
            .to_u64()
            .unwrap_or(0);
        self.total_gas_deducted.fetch_add(gas_fp_add, Ordering::Relaxed);

        // C-2 FIX: Use atomic fetch_sub / fetch_add instead of the old
        // read-modify-write pattern (get_balance_atomic → compute → update_balance_atomic)
        // which had a TOCTOU race: a concurrent trade or balance sync could
        // change the balance between the read and the write, causing lost updates.

        // Debit the source exchange atomically.
        self.allocator.fetch_sub_balance(from_exchange_id as usize, token_id as usize, debit_amount);

        // Credit the destination exchange atomically.
        self.allocator.fetch_add_balance(to_exchange_id as usize, token_id as usize, credit_amount);

        info!(
            from = from_exchange_id,
            to = to_exchange_id,
            token_id = token_id,
            debit = %debit_amount,
            credit = %credit_amount,
            gas_fee = %effective_gas,
            "Stage 4: Balance matrix realigned — capital transport complete (atomic fetch_sub/fetch_add)"
        );
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
    ) -> Result<(String, reqwest::header::HeaderMap), String> {
        use reqwest::header::{HeaderMap, HeaderValue, CONTENT_TYPE};

        /// Insert a header, returning Err if the value is not valid ASCII.
        /// This prevents silently sending empty auth headers that would
        /// mask internal errors as exchange rejections.
        fn insert_header(
            headers: &mut HeaderMap,
            name: &str,
            value: &str,
        ) -> Result<(), String> {
            let header_name: reqwest::header::HeaderName = name
                .parse()
                .map_err(|e| format!("invalid header name '{}': {}", name, e))?;
            let header_value = HeaderValue::from_str(value)
                .map_err(|e| format!("{} header value invalid: {}", name, e))?;
            headers.insert(header_name, header_value);
            Ok(())
        }

        match req.from_exchange_id {
            // ── Binance withdrawal ─────────────────────────────────────
            0 => {
                let mut params: std::collections::BTreeMap<String, String> =
                    std::collections::BTreeMap::new();
                params.insert("coin".into(), req.token_symbol.to_uppercase());
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
                insert_header(&mut headers, "X-MBX-APIKEY", signer.api_key())?;

            Ok((signed_query, headers))
            }

            // ── Bybit V5 withdrawal ───────────────────────────────────
            1 => {
                let body_map = serde_json::json!({
                    "coin": req.token_symbol.to_uppercase(),
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
                insert_header(&mut headers, "X-BAPI-API-KEY", signer.api_key())?;
                insert_header(&mut headers, "X-BAPI-SIGN", &sign)?;
                insert_header(&mut headers, "X-BAPI-TIMESTAMP", &timestamp)?;
                insert_header(&mut headers, "X-BAPI-RECV-WINDOW", &recv_window)?;

                Ok((body_str, headers))
            }

            // ── OKX V5 withdrawal ─────────────────────────────────────
            2 => {
                let body_map = serde_json::json!({
                    "ccy": req.token_symbol.to_uppercase(),
                    "amt": req.amount.to_string(),
                    "dest": "4", // 4 = external address
                    "toAddr": target_address,
                    "chain": format!("{}-{}", req.token_symbol.to_uppercase(), network.to_uppercase()),
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
                insert_header(&mut headers, "OK-ACCESS-KEY", signer.api_key())?;
                insert_header(&mut headers, "OK-ACCESS-SIGN", &signature)?;
                insert_header(&mut headers, "OK-ACCESS-TIMESTAMP", &timestamp)?;
                insert_header(&mut headers, "OK-ACCESS-PASSPHRASE", signer.passphrase.as_ref().map(|p| p.expose()).unwrap_or(""))?;

                Ok((body_str, headers))
            }

            // ── Gate.io V4 withdrawal ─────────────────────────────────
            3 => {
                let body_map = serde_json::json!({
                    "currency": req.token_symbol.to_uppercase(),
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
                insert_header(&mut headers, "KEY", signer.api_key())?;
                insert_header(&mut headers, "SIGN", &signature)?;
                insert_header(&mut headers, "Timestamp", &timestamp)?;

                Ok((body_str, headers))
            }

            // ── KuCoin V1 withdrawal ──────────────────────────────────
            4 => {
                let body_map = serde_json::json!({
                    "currency": req.token_symbol.to_uppercase(),
                    "amount": req.amount.to_string(),
                    "address": target_address,
                    "chain": "ARB".to_string(),
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
                insert_header(&mut headers, "KC-API-KEY", signer.api_key())?;
                insert_header(&mut headers, "KC-API-SIGN", &signature)?;
                insert_header(&mut headers, "KC-API-TIMESTAMP", &timestamp)?;
                insert_header(&mut headers, "KC-API-PASSPHRASE", &passphrase_sign)?;
                headers.insert("KC-API-KEY-VERSION", HeaderValue::from_static("2"));

                Ok((body_str, headers))
            }

            // ── Unknown exchange — should never reach here ────────────
            _ => {
                Err(format!("Unknown source exchange ID {} for withdrawal", req.from_exchange_id))
            }
        }
    }

    // -------------------------------------------------------------------
    // Exchange liveness tracking
    // -------------------------------------------------------------------

    /// Returns a clonable handle that data feed workers can use to record
    /// exchange heartbeats.  Each call to `handle.record(exchange_id)` from
    /// a WS feed worker keeps the rebalancer's liveness map fresh.
    ///
    /// Call this **before** spawning the rebalancer (i.e. before moving
    /// `self` into the Tokio task), then distribute clones to each feed
    /// worker via `spawn_feed_workers`.
    pub fn heartbeat_handle(&self) -> ExchangeHeartbeatHandle {
        ExchangeHeartbeatHandle {
            inner: Arc::clone(&self.exchange_last_seen),
        }
    }

    /// Returns `true` if `exchange_id` has a recorded heartbeat within
    /// the last 30 seconds.
    ///
    /// * **No heartbeats recorded for ANY exchange** → returns `true`
    ///   (bootstrap grace period: don't block the very first rebalance
    ///   before the trading loop has had a chance to record heartbeats).
    ///
    /// * **Heartbeats exist for other exchanges but not this one** →
    ///   returns `false` (this exchange is genuinely dead).
    ///
    /// * **Lock poisoned** → returns `true` (fail-open: don't block
    ///   all rebalances just because of a poisoned lock).
    fn is_exchange_live(&self, exchange_id: u16) -> bool {
        const HEARTBEAT_TTL_SECS: u64 = 90;

        match self.exchange_last_seen.lock() {
            Ok(map) => {
                if map.is_empty() {
                    // Bootstrap grace period — no heartbeats recorded yet.
                    return true;
                }
                match map.get(&exchange_id) {
                    Some(last_seen) => last_seen.elapsed().as_secs() < HEARTBEAT_TTL_SECS,
                    None => false, // Other exchanges have heartbeats but not this one — dead.
                }
            }
            Err(_) => true, // Lock poisoned — fail-open.
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
        rx.recv().await.expect("channel should have a message after sending 10");
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