//! Dead Man's Switch — Heartbeat-based watchdog.
//!
//! If no heartbeat is received within the configured timeout, the watchdog
//! trips and kills all trading activity.  This is a last-resort safety
//! mechanism for unattended production deployments.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::time::sleep;

/// Reason the dead man's switch was triggered.
pub const REASON_MANUAL_KILL: &str = "MANUAL_KILL";

/// A heartbeat-based watchdog that will flip a kill flag if heartbeats stop.
///
/// Usage:
///   1. Create with `DeadMansSwitch::new(grace_period, timeout)`.
///   2. Spawn the watchdog task with `spawn_dead_mans_watchdog()`.
///   3. Call `heartbeat()` from the main signal loop every tick.
///   4. Check `is_tripped()` before every trade.
pub struct DeadMansSwitch {
    /// Monotonic counter — incremented on every heartbeat.
    pub last_heartbeat_ms: AtomicU64,
    /// Flipped to `true` when the watchdog trips.  All trading must stop.
    pub tripped: AtomicBool,
    /// Grace period after startup before the watchdog starts checking (ms).
    grace_period_ms: u64,
    /// Timeout with no heartbeat before tripping (ms).
    timeout_ms: u64,
}

impl DeadMansSwitch {
    /// Creates a new dead man's switch.
    ///
    /// # Arguments
    /// * `grace_period_secs` — Seconds after startup before enforcement begins.
    /// * `timeout_secs` — Seconds without a heartbeat before tripping.
    pub fn new(grace_period_secs: u64, timeout_secs: u64) -> Self {
        Self {
            last_heartbeat_ms: AtomicU64::new(now_ms()),
            tripped: AtomicBool::new(false),
            grace_period_ms: grace_period_secs * 1000,
            timeout_ms: timeout_secs * 1000,
        }
    }

    /// Record a heartbeat.  Call this from the signal loop every tick.
    pub fn heartbeat(&self) {
        self.last_heartbeat_ms.store(now_ms(), Ordering::Release);
    }

    /// Check if the switch has been tripped.
    #[inline(always)]
    pub fn is_tripped(&self) -> bool {
        self.tripped.load(Ordering::Acquire)
    }

    /// Manually trip the switch (e.g., from a SIGINT handler).
    pub fn trip(&self, reason: &str) {
        tracing::error!(reason = reason, "dead man's switch manually tripped");
        self.tripped.store(true, Ordering::Release);
    }

    /// Returns the elapsed time since the last heartbeat, in milliseconds.
    pub fn elapsed_since_heartbeat_ms(&self) -> u64 {
        now_ms().saturating_sub(self.last_heartbeat_ms.load(Ordering::Acquire))
    }
}

/// Spawns the watchdog task.  This runs in the background and trips the
/// switch if no heartbeat is received within the timeout.
pub fn spawn_dead_mans_watchdog(switch: Arc<DeadMansSwitch>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        // Wait for the grace period before starting enforcement.
        sleep(Duration::from_millis(switch.grace_period_ms)).await;
        tracing::info!(
            grace_s = switch.grace_period_ms / 1000,
            timeout_s = switch.timeout_ms / 1000,
            "dead man's switch watchdog active"
        );

        loop {
            sleep(Duration::from_millis(1000)).await;
            if switch.is_tripped() {
                return; // Already tripped — exit the watcher.
            }
            let elapsed = switch.elapsed_since_heartbeat_ms();
            if elapsed > switch.timeout_ms {
                tracing::error!(
                    elapsed_ms = elapsed,
                    timeout_ms = switch.timeout_ms,
                    "DEAD MAN'S SWITCH TRIPPED — no heartbeat for {}ms, killing all trading",
                    elapsed
                );
                switch.tripped.store(true, Ordering::Release);
                return;
            }
        }
    })
}

/// Returns the current time in milliseconds since UNIX epoch.
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_heartbeat_updates_timestamp() {
        let dms = DeadMansSwitch::new(0, 60);
        let before = dms.last_heartbeat_ms.load(Ordering::Acquire);
        std::thread::sleep(std::time::Duration::from_millis(5));
        dms.heartbeat();
        let after = dms.last_heartbeat_ms.load(Ordering::Acquire);
        assert!(after >= before);
    }

    #[test]
    fn test_manual_trip() {
        let dms = DeadMansSwitch::new(0, 60);
        assert!(!dms.is_tripped());
        dms.trip("test");
        assert!(dms.is_tripped());
    }

    #[test]
    fn test_elapsed_increases() {
        let dms = DeadMansSwitch::new(0, 60);
        dms.heartbeat();
        std::thread::sleep(std::time::Duration::from_millis(10));
        let elapsed = dms.elapsed_since_heartbeat_ms();
        assert!(elapsed >= 10);
    }
}