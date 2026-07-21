// discord.rs — Non-blocking Discord webhook notification worker.
//
// The main trading loop drops tiny payload structs into a bounded MPSC
// channel.  A low-priority background task picks them up, serialises the
// JSON embed payloads, and POSTs to the configured Discord webhook URL.
//
// Three payload schemas:
//   * CrossExchangeFill  (green embed) — two-leg arbitrage execution.
//   * TriangularFill      (blue embed)  — three-leg loop completion.
//   * RiskBreakerTrip     (red embed)   — emergency protection layer trip.
//
// The worker is fully decoupled from the hot path: no allocations, no
// locks, no blocking I/O inside the execution engine.

use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::json;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

/// Maximum number of retry attempts for a failed webhook send.
const DISCORD_MAX_RETRIES: u32 = 3;

/// Base delay in milliseconds for exponential backoff on retry.
const DISCORD_BASE_RETRY_MS: f64 = 100.0;

/// Discord embed color: green (cross-exchange fill).
const DISCORD_COLOR_GREEN: u32 = 65_280;

/// Discord embed color: blue (triangular fill).
const DISCORD_COLOR_BLUE: u32 = 255;

/// Discord embed color: red (risk breaker trip).
const DISCORD_COLOR_RED: u32 = 16_711_680;

/// Discord embed color: blurple (system info, Discord brand).
const DISCORD_COLOR_BLURPLE: u32 = 3_066_993;

/// Minimum interval between Discord webhook sends (200ms = 5/sec).
const DISCORD_RATE_LIMIT_MS: u64 = 200;

// ---------------------------------------------------------------------------
// Notification payloads
// ---------------------------------------------------------------------------

/// A single notification event to be sent to Discord.
///
/// The worker serializes this into a Discord embed payload and POSTs
/// it to the configured webhook URL. No secrets or API keys are
/// included in the payload.
#[derive(Debug, Clone)]
pub enum DiscordNotification {
    /// Two-leg cross-exchange arbitrage fill.
    CrossExchangeFill {
        token_id: u16,
        symbol: String,
        total_size_usd: String,
        leg_a_exchange: String,
        leg_a_price: String,
        leg_b_exchange: String,
        leg_b_price: String,
        gross_spread_pct: String,
        net_yield_usdt: String,
        execution_latency_us: u64,
        pipeline: String,
    },
    /// Three-leg triangular arbitrage loop.
    TriangularFill {
        exchange: String,
        loop_route: String,
        input_capital_usdt: String,
        final_payout_usdt: String,
        net_yield_pct: String,
        net_yield_usdt: String,
        execution_latency_us: u64,
        pipeline: String,
    },
    /// Emergency risk breaker trip.
    RiskBreakerTrip {
        layer_name: String,
        violation_detail: String,
    },
    /// Startup / shutdown / info message.
    SystemInfo {
        title: String,
        description: String,
        fields: Vec<(String, String)>,
    },
}

// ---------------------------------------------------------------------------
// DiscordWorker — background sender task
// ---------------------------------------------------------------------------

/// Background worker that receives notifications and POSTs them to Discord.
///
/// The webhook URL is held internally and is never logged or included
/// in error messages to prevent credential leakage (category K).
pub struct DiscordWorker {
    webhook_url: String,
    receiver: mpsc::Receiver<DiscordNotification>,
    http: reqwest::Client,
    /// L-1: Instant of the last successful send, for rate limiting.
    last_send: std::sync::Mutex<std::time::Instant>,
}

impl DiscordWorker {
    /// Creates a new worker and its sender half.
    ///
    /// Returns `(worker, sender)`.  Spawn `worker.run()` as a background
    /// tokio task.  Use `sender` from the hot path.
    ///
    /// # Arguments
    /// * `webhook_url` — Discord webhook URL (must start with `https://`)
    /// * `buffer_capacity` — Bounded channel capacity for pending notifications
    pub fn new(
        webhook_url: String,
        buffer_capacity: usize,
    ) -> (Self, mpsc::Sender<DiscordNotification>) {
        let (tx, rx) = mpsc::channel(buffer_capacity);
        let worker = Self {
            webhook_url,
            receiver: rx,
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(5))
                .connect_timeout(std::time::Duration::from_secs(3))
                .pool_max_idle_per_host(2)
                .build()
                .unwrap_or_else(|e| {
                    tracing::error!("failed to build Discord HTTP client: {}, using default", e);
                    reqwest::Client::new()
                }),
            // L-1: Initialise to an instant well in the past so the first send is never delayed.
            last_send: std::sync::Mutex::new(
                std::time::Instant::now() - std::time::Duration::from_secs(10),
            ),
        };
        (worker, tx)
    }

    /// L-1: Enforces the minimum interval between sends. Returns the
    /// remaining time to wait if called too soon, or None if ok to send.
    fn enforce_rate_limit(&self) -> Option<std::time::Duration> {
        let last = {
            let guard = self.last_send.lock().unwrap_or_else(|e| e.into_inner());
            *guard
        };
        let elapsed = last.elapsed();
        let min_interval = std::time::Duration::from_millis(DISCORD_RATE_LIMIT_MS);
        if elapsed < min_interval {
            Some(min_interval - elapsed)
        } else {
            None
        }
    }

    /// Main event loop — runs until all senders are dropped.
    ///
    /// Failed sends are retried up to 3 times with exponential backoff
    /// (100 ms × 2^attempt).  All failures are logged; no alert is ever
    /// silently dropped.
    ///
    /// L-1: Rate limiting enforced — minimum 200ms between sends to
    /// respect Discord's 5 requests/second webhook limit.
    pub async fn run(mut self) {
        info!("Discord notification worker started");

        while let Some(notification) = self.receiver.recv().await {
            // L-1: Rate-limit enforcement — sleep if needed.
            if let Some(wait) = self.enforce_rate_limit() {
                tokio::time::sleep(wait).await;
            }

            let payload = build_embed_payload(&notification);

            const MAX_RETRIES: u32 = DISCORD_MAX_RETRIES;
            let mut attempt: u32 = 0;

            loop {
                match self
                    .http
                    .post(&self.webhook_url)
                    .header("Content-Type", "application/json")
                    .json(&payload)
                    .send()
                    .await
                {
                    Ok(resp) if resp.status().is_success() => {
                        debug!("discord notification sent");
                        // L-1: Record successful send time for rate limiting.
                        {
                            let mut guard = self.last_send.lock().unwrap_or_else(|e| e.into_inner());
                            *guard = std::time::Instant::now();
                        }
                        break;
                    }
                    Ok(resp) => {
                        let status = resp.status();
                        let body = resp.text().await.unwrap_or_default();
                        if status.as_u16() == 204 {
                            break;
                        }
                        attempt += 1;
                        if attempt >= MAX_RETRIES {
                            warn!(
                                %status,
                                %body,
                                attempts = attempt,
                                "discord webhook failed after all retries"
                            );
                            break;
                        }
                        let base_ms = DISCORD_BASE_RETRY_MS * (1u32.checked_shl(attempt).unwrap_or(1u32 << 30)) as f64;
                        let jittered_ms = base_ms * (0.75 + 0.5 * rand::random::<f64>());
                        let delay = std::time::Duration::from_millis(jittered_ms as u64);
                        warn!(
                            %status,
                            attempt,
                            next_retry_ms = delay.as_millis(),
                            "discord webhook non-success, retrying with jitter"
                        );
                        tokio::time::sleep(delay).await;
                    }
                    Err(e) => {
                        attempt += 1;
                        if attempt >= MAX_RETRIES {
                            // K: Sanitize error — reqwest::Error::to_string() may
                            // include the webhook URL which contains query params.
                            warn!(
                                status = %e.status().unwrap_or_default(),
                                attempts = attempt,
                                "discord notification failed after all retries"
                            );
                            break;
                        }
                        let base_ms = DISCORD_BASE_RETRY_MS * (1u32.checked_shl(attempt).unwrap_or(1u32 << 30)) as f64;
                        let jittered_ms = base_ms * (0.75 + 0.5 * rand::random::<f64>());
                        let delay = std::time::Duration::from_millis(jittered_ms as u64);
                        warn!(
                            status = %e.status().unwrap_or_default(),
                            attempt,
                            next_retry_ms = delay.as_millis(),
                            "discord notification error, retrying with jitter"
                        );
                        tokio::time::sleep(delay).await;
                    }
                }
            }
        }

        info!("Discord notification worker shut down");
    }
}

// ---------------------------------------------------------------------------
// Payload builders
// ---------------------------------------------------------------------------

/// Build the JSON value for a Discord webhook POST from a notification.
fn build_embed_payload(notification: &DiscordNotification) -> serde_json::Value {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| {
            chrono::DateTime::from_timestamp_millis(d.as_millis() as i64)
                .map(|dt| dt.format("%Y-%m-%dT%H:%M:%S.000Z").to_string())
                .unwrap_or_default()
        })
        .unwrap_or_default();

    let (title, description, color, fields, footer_text) = match notification {
        DiscordNotification::CrossExchangeFill {
            symbol,
            total_size_usd,
            leg_a_exchange,
            leg_a_price,
            leg_b_exchange,
            leg_b_price,
            gross_spread_pct,
            net_yield_usdt,
            execution_latency_us,
            pipeline,
            ..
        } => (
            "🎯 CROSS-EXCHANGE ARBITRAGE FILL".to_string(),
            "Successfully captured a price discrepancy between exchanges.".to_string(),
            DISCORD_COLOR_GREEN,
            vec![
                json!({"name": "Asset Symbol", "value": symbol, "inline": true}),
                json!({"name": "Total Size Allocated", "value": total_size_usd, "inline": true}),
                json!({"name": "Leg A (Buy)", "value": format!("{} @ {}", leg_a_exchange, leg_a_price), "inline": true}),
                json!({"name": "Leg B (Sell)", "value": format!("{} @ {}", leg_b_exchange, leg_b_price), "inline": true}),
                json!({"name": "Gross Spread Capture", "value": gross_spread_pct, "inline": true}),
                json!({"name": "Net Pure Yield", "value": net_yield_usdt, "inline": true}),
            ],
            format!(
                "Execution latency: {} us | Pipeline: {}",
                execution_latency_us, pipeline
            ),
        ),

        DiscordNotification::TriangularFill {
            exchange,
            loop_route,
            input_capital_usdt,
            final_payout_usdt,
            net_yield_pct,
            net_yield_usdt,
            execution_latency_us,
            pipeline,
        } => (
            "🔄 TRIANGULAR ARBITRAGE LOOP COMPLETION".to_string(),
            "Internal cycle execution cleared successfully on a single exchange.".to_string(),
            DISCORD_COLOR_BLUE,
            vec![
                json!({"name": "Exchange Venue", "value": exchange, "inline": true}),
                json!({"name": "Loop Routing Track", "value": loop_route, "inline": false}),
                json!({"name": "Initial Input Capital", "value": input_capital_usdt, "inline": true}),
                json!({"name": "Final Payout Balance", "value": final_payout_usdt, "inline": true}),
                json!({"name": "Net Yield Generation", "value": format!("{} ({})", net_yield_pct, net_yield_usdt), "inline": true}),
            ],
            format!(
                "Execution latency: {} us | Pipeline: {}",
                execution_latency_us, pipeline
            ),
        ),

        DiscordNotification::RiskBreakerTrip {
            layer_name,
            violation_detail,
        } => (
            "🚨 EMERGENCY FINANCIAL BREAKER TRIP".to_string(),
            "The risk management engine has intervened to lock down capital.".to_string(),
            DISCORD_COLOR_RED,
            vec![
                json!({"name": "Triggered Layer Gate", "value": layer_name, "inline": true}),
                json!({"name": "Violation Parameter", "value": violation_detail, "inline": true}),
                json!({"name": "System Status", "value": "GLOBAL TRADING LOCKED DOWN", "inline": false}),
            ],
            "Action taken in <1 microsecond | All strategies halted instantly.".to_string(),
        ),

        DiscordNotification::SystemInfo {
            title,
            description,
            fields: info_fields,
        } => (
            format!("🚀 {}", title),
            description.clone(),
            DISCORD_COLOR_BLURPLE,
            info_fields
                .iter()
                .map(|(k, v)| json!({"name": k, "value": v, "inline": true}))
                .collect(),
            "HFT Arbitrage Engine".to_string(),
        ),
    };

    json!({
        "embeds": [{
            "title": title,
            "description": description,
            "color": color,
            "fields": fields,
            "footer": { "text": footer_text },
            "timestamp": timestamp,
        }]
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cross_exchange_fill_payload_structure() {
        let notif = DiscordNotification::CrossExchangeFill {
            token_id: 2,
            symbol: "SOL (ID 2)".to_string(),
            total_size_usd: "$500.00 USDT".to_string(),
            leg_a_exchange: "Binance".to_string(),
            leg_a_price: "$142.00".to_string(),
            leg_b_exchange: "KuCoin".to_string(),
            leg_b_price: "$142.50".to_string(),
            gross_spread_pct: "+0.35%".to_string(),
            net_yield_usdt: "+$1.25 USDT".to_string(),
            execution_latency_us: 4800,
            pipeline: "REAL".to_string(),
        };

        let payload = build_embed_payload(&notif);
        let embeds = payload["embeds"].as_array().unwrap();
        assert_eq!(embeds.len(), 1);

        let embed = &embeds[0];
        assert_eq!(embed["title"], "🎯 CROSS-EXCHANGE ARBITRAGE FILL");
        assert_eq!(embed["color"], 65280);

        let fields = embed["fields"].as_array().unwrap();
        assert_eq!(fields.len(), 6);
        assert_eq!(fields[0]["name"], "Asset Symbol");
        assert_eq!(fields[0]["value"], "SOL (ID 2)");

        let footer = embed["footer"]["text"].as_str().unwrap();
        assert!(footer.contains("4800"));
        assert!(footer.contains("REAL"));
    }

    #[test]
    fn test_triangular_fill_payload_structure() {
        let notif = DiscordNotification::TriangularFill {
            exchange: "Binance (ID 0)".to_string(),
            loop_route: "USDT ➔ BTC ➔ ETH ➔ USDT".to_string(),
            input_capital_usdt: "$250.00 USDT".to_string(),
            final_payout_usdt: "$250.45 USDT".to_string(),
            net_yield_pct: "+0.18%".to_string(),
            net_yield_usdt: "+$0.45 USDT".to_string(),
            execution_latency_us: 2100,
            pipeline: "PAPER".to_string(),
        };

        let payload = build_embed_payload(&notif);
        let embed = &payload["embeds"].as_array().unwrap()[0];
        assert_eq!(embed["title"], "🔄 TRIANGULAR ARBITRAGE LOOP COMPLETION");
        assert_eq!(embed["color"], 255);

        let fields = embed["fields"].as_array().unwrap();
        assert_eq!(fields.len(), 5);
    }

    #[test]
    fn test_risk_breaker_payload_structure() {
        let notif = DiscordNotification::RiskBreakerTrip {
            layer_name: "Layer 6: Stablecoin Peg Breaker".to_string(),
            violation_detail: "USDT Price deviated to $0.9920".to_string(),
        };

        let payload = build_embed_payload(&notif);
        let embed = &payload["embeds"].as_array().unwrap()[0];
        assert_eq!(embed["title"], "🚨 EMERGENCY FINANCIAL BREAKER TRIP");
        assert_eq!(embed["color"], 16_711_680);

        let fields = embed["fields"].as_array().unwrap();
        assert_eq!(fields[2]["value"], "GLOBAL TRADING LOCKED DOWN");
    }

    #[test]
    fn test_system_info_payload_structure() {
        let notif = DiscordNotification::SystemInfo {
            title: "HFT CORE ENGINE ONLINE".to_string(),
            description: "Modular quantitative framework compiled and running on physical Core 0.".to_string(),
            fields: vec![
                ("Server Node".to_string(), "Dedicated Tokyo Bare-Metal".to_string()),
                ("Memory Baseline".to_string(), "Flat line @ 420 MB / 8 GB Limit".to_string()),
            ],
        };

        let payload = build_embed_payload(&notif);
        let embed = &payload["embeds"].as_array().unwrap()[0];
        assert!(embed["title"].as_str().unwrap().contains("HFT CORE ENGINE ONLINE"));

        let fields = embed["fields"].as_array().unwrap();
        assert_eq!(fields.len(), 2);
    }

    #[tokio::test]
    async fn test_discord_worker_creation() {
        let (worker, sender) = DiscordWorker::new(
            "https://discord.com/api/webhooks/fake/test".to_string(),
            10,
        );

        // Verify we can send into the channel
        assert!(sender.send(DiscordNotification::SystemInfo {
            title: "TEST".to_string(),
            description: "test".to_string(),
            fields: vec![],
        }).await.is_ok());

        // Verify worker fields are set
        assert_eq!(worker.webhook_url, "https://discord.com/api/webhooks/fake/test");
    }
}