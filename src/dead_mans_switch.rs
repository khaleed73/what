//! Dead-Man's Switch — Automatic kill switch if the operator goes unresponsive.
//!
//! In production HFT, the bot must be continuously supervised. This module
//! implements a "dead-man's switch" that requires periodic heartbeats from
//! an external supervisor (e.g., a monitoring service, watchdog process, or
//! human operator via a health-check endpoint). If no heartbeat is received
//! within the configured timeout, the system trips the circuit breaker and
//! cancels all outstanding orders.
//!
//! Heartbeat sources:
//!   - HTTP health endpoint (GET /healthz returns 200 only if alive)
//!   - External watchdog process touching a sentinel file
//!   - Manual `hftctl heartbeat` CLI command

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Default timeout: if no heartbeat for 60 seconds, trip the breaker.
const DEFAULT_TIMEOUT_SECS: u64 = 60;

/// Grace period after startup before the switch becomes active.
/// Prevents false trips during slow boot sequences.
const GRACE_PERIOD_SECS: u64 = 30;

pub struct DeadMansSwitch {
    /// Timestamp (ms since epoch) of the last received heartbeat.
    last_heartbeat_ms: AtomicU64,
    /// Whether the switch has been tripped.
    tripped: AtomicBool,
    /// Timeout in milliseconds.
    timeout_ms: u64,
    /// Whether the grace period has elapsed.
    grace_elapsed: AtomicBool,
    /// Startup timestamp for grace period calculation.
    startup_ms: u64,
}

impl DeadMansSwitch {
    pub fn new(timeout_secs: u64) -> Self {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        Self {
            last_heartbeat_ms: AtomicU64::new(now_ms),
            tripped: AtomicBool::new(false),
            timeout_ms: timeout_secs * 1000,
            grace_elapsed: AtomicBool::new(false),
            startup_ms: now_ms,
        }
    }

    /// Creates a switch with the default 60-second timeout.
    pub fn with_defaults() -> Self {
        Self::new(DEFAULT_TIMEOUT_SECS)
    }

    /// Record a heartbeat from the supervisor.
    pub fn heartbeat(&self) {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        self.last_heartbeat_ms.store(now_ms, Ordering::SeqCst);
        // If previously tripped, a heartbeat resets the switch (manual recovery).
        if self.tripped.load(Ordering::SeqCst) {
            tracing::info!("DEAD-MAN'S SWITCH: heartbeat received — resetting tripped state");
            self.tripped.store(false, Ordering::SeqCst);
        }
    }

    /// Check if the switch has tripped due to heartbeat timeout.
    /// Returns true if the system should halt all trading.
    pub fn check(&self) -> bool {
        // During grace period, don't trip.
        if !self.grace_elapsed.load(Ordering::SeqCst) {
            let now_ms = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0);
            if now_ms - self.startup_ms < GRACE_PERIOD_SECS * 1000 {
                return false;
            }
            self.grace_elapsed.store(true, Ordering::SeqCst);
        }

        if self.tripped.load(Ordering::SeqCst) {
            return true;
        }

        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let last = self.last_heartbeat_ms.load(Ordering::SeqCst);
        let elapsed_ms = now_ms.saturating_sub(last);

        if elapsed_ms > self.timeout_ms {
            let was_tripped = self.tripped.swap(true, Ordering::SeqCst);
            if !was_tripped {
                tracing::error!(
                    elapsed_secs = elapsed_ms / 1000,
                    timeout_secs = self.timeout_ms / 1000,
                    "DEAD-MAN'S SWITCH TRIPPED — no heartbeat for {}s (timeout: {}s). \
                     All trading HALTED. Send a heartbeat to recover.",
                    elapsed_ms / 1000,
                    self.timeout_ms / 1000,
                );
            }
            true
        } else {
            false
        }
    }

    /// Returns the number of milliseconds since the last heartbeat.
    pub fn millis_since_last_heartbeat(&self) -> u64 {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let last = self.last_heartbeat_ms.load(Ordering::SeqCst);
        now_ms.saturating_sub(last)
    }

    /// Whether the switch is currently tripped.
    pub fn is_tripped(&self) -> bool {
        self.tripped.load(Ordering::SeqCst)
    }

    /// Manually trip the switch (equivalent to operator kill).
    pub fn manual_trip(&self) {
        self.tripped.store(true, Ordering::SeqCst);
        tracing::error!("DEAD-MAN'S SWITCH: manually tripped by operator");
    }
}

/// Spawns a background task that checks the dead-man's switch every second.
/// If tripped, it calls the provided `on_trip` callback.
pub fn spawn_dead_mans_watchdog(
    switch: Arc<DeadMansSwitch>,
    on_trip: Arc<dyn Fn() + Send + Sync>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        loop {
            interval.tick().await;
            if switch.check() {
                on_trip();
            }
        }
    })
}