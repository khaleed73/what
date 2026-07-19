use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing;

// ---------------------------------------------------------------------------
// PersistentState – the serialisable snapshot the bot persists to disk
// ---------------------------------------------------------------------------

/// Snapshot of all durable bot state that must survive a restart.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistentState {
    /// Paper-trading USD balance.
    pub paper_usd_balance: Decimal,
    /// True when the risk engine has frozen all trading.
    pub is_system_risk_frozen: bool,
    /// Cumulative session P&L in **cents** (integer to avoid floating-point drift).
    pub session_pnl_cents: i64,
    /// Total number of trades executed in this session.
    pub total_trades: u64,
    /// Unix-epoch seconds of the last state update.
    pub timestamp: i64,
    /// Per-exchange failure counts (exchange_id → consecutive failures).
    pub exchange_health: HashMap<u16, u32>,
}

impl Default for PersistentState {
    fn default() -> Self {
        Self {
            paper_usd_balance: Decimal::ZERO,
            is_system_risk_frozen: false,
            session_pnl_cents: 0,
            total_trades: 0,
            timestamp: 0,
            exchange_health: HashMap::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// AsyncPersistenceWorker – background task that serialises state to disk
// ---------------------------------------------------------------------------

/// A long-lived background worker that receives [`PersistentState`] updates over a
/// bounded MPSC channel and writes them to a JSON file on disk.
///
/// The worker also performs periodic "flush" saves at `flush_interval_secs`
/// intervals. This is a no-op if nothing changed but guarantees the file
/// exists on disk (useful after a fresh start).
pub struct AsyncPersistenceWorker {
    /// Path to the JSON state file.
    pub state_file_path: String,
    /// Receiver half of the bounded MPSC channel.
    pub receiver: mpsc::Receiver<PersistentState>,
    /// Seconds between periodic auto-save ticks.
    pub flush_interval_secs: u64,
}

impl AsyncPersistenceWorker {
    /// Create a new persistence worker and its sender half.
    ///
    /// Returns a tuple of `(worker, sender)`.  Spawn `worker.run_disk_writer_loop()`
    /// in a dedicated tokio task; use `sender` from the hot path to enqueue state
    /// snapshots.
    pub fn new(path: &str, capacity: usize) -> (Self, mpsc::Sender<PersistentState>) {
        let (tx, rx) = mpsc::channel(capacity);
        let worker = Self {
            state_file_path: path.to_string(),
            receiver: rx,
            flush_interval_secs: 30,
        };
        (worker, tx)
    }

    /// Main event loop – runs until the sender half is dropped.
    ///
    /// * **Message branch** – serialise the incoming `PersistentState` to pretty
    ///   JSON and atomically write it to `state_file_path`.
    /// * **Timer branch** – periodically re-save whatever is currently on disk
    ///   (effectively a no-op that guarantees the file exists).
    pub async fn run_disk_writer_loop(mut self) {
        let mut flush_tick = tokio::time::interval(Duration::from_secs(self.flush_interval_secs));

        loop {
            tokio::select! {
                // ---- incoming state snapshot ----
                maybe_state = self.receiver.recv() => {
                    match maybe_state {
                        Some(state) => {
                            if let Err(err) = self.save_state(&state).await {
                                tracing::error!(
                                    path = %self.state_file_path,
                                    error = %err,
                                    "failed to persist state to disk"
                                );
                            }
                        }
                        // Sender dropped – drain is complete, exit loop.
                        None => {
                            tracing::info!("persistence channel closed, shutting down disk writer");
                            break;
                        }
                    }
                }

                // ---- periodic flush tick ----
                _ = flush_tick.tick() => {
                    match self.load_state() {
                        Ok(current) => {
                            if let Err(err) = self.save_state(&current).await {
                                tracing::error!(
                                    path = %self.state_file_path,
                                    error = %err,
                                    "periodic flush failed"
                                );
                            }
                        }
                        Err(err) => {
                            // File doesn't exist yet or is corrupt — skip this
                            // tick.  Writing a default state here would wipe the
                            // in-memory P&L and balances, which is catastrophic.
                            tracing::warn!(
                                error = %err,
                                "periodic flush could not load state; skipping write to avoid wiping in-memory data"
                            );
                        }
                    }
                }
            }
        }
    }

    /// Serialise `state` to pretty-printed JSON and write it to
    /// `self.state_file_path`.
    ///
    /// The write is performed inside `tokio::task::spawn_blocking` so that the
    /// async runtime is not blocked by file I/O.
    pub async fn save_state(&self, state: &PersistentState) -> Result<(), String> {
        let json = serde_json::to_string_pretty(state)
            .map_err(|e| format!("serialize failed: {}", e))?;

        let path = self.state_file_path.clone();

        tokio::task::spawn_blocking(move || {
            // Write to a temporary file next to the target, then atomically rename.
            // This avoids corrupting the file on a mid-write crash.
            let tmp_path = format!("{}.tmp", path);
            fs::write(&tmp_path, &json).map_err(|e| format!("write tmp failed: {}", e))?;
            // Ensure data is durable on disk before the atomic rename,
            // otherwise the OS could lose buffered writes on crash.
            let file = std::fs::File::open(&tmp_path)
                .map_err(|e| format!("open for sync failed: {}", e))?;
            file.sync_all()
                .map_err(|e| format!("sync_all failed: {}", e))?;
            // M-10: EXDEV fallback — rename fails across filesystems.
            if let Err(e) = fs::rename(&tmp_path, &path) {
                if e.raw_os_error() == Some(18) {
                    // EXDEV: cross-device link — copy + delete instead.
                    // NOTE: 18 is libc::EXDEV on Linux/macOS (POSIX).
                    // On Windows this branch will never match.
                    std::fs::copy(&tmp_path, &path).map_err(|e| format!("EXDEV copy failed: {}", e))?;
                    std::fs::remove_file(&tmp_path).map_err(|e| format!("EXDEV cleanup failed: {}", e))?;
                } else {
                    return Err(format!("rename failed: {}", e));
                }
            }
            Ok(())
        })
        .await
        .map_err(|e| format!("spawn_blocking join error: {}", e))?
    }

    /// Read `self.state_file_path`, deserialize JSON into [`PersistentState`].
    ///
    /// If the file does not exist a fresh default is returned.
    pub fn load_state(&self) -> Result<PersistentState, String> {
        let path = Path::new(&self.state_file_path);
        if !path.exists() {
            return Ok(PersistentState::default());
        }

        let contents = fs::read_to_string(path).map_err(|e| format!("read failed: {}", e))?;
        let state: PersistentState = serde_json::from_str(&contents).map_err(|e| format!("parse failed: {}", e))?;
        Ok(state)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use tokio::time::{timeout, Duration};

    #[test]
    fn test_save_and_load_roundtrip() {
        let dir = std::env::temp_dir().join("rust_hft_arb_test");
        let _ = std::fs::create_dir_all(&dir);
        let file_path = dir.join("state.json");
        let path_str = file_path.to_str().unwrap().to_string();

        // Build a non-trivial state.
        let mut exchange_health = HashMap::new();
        exchange_health.insert(1, 5);
        exchange_health.insert(2, 0);
        exchange_health.insert(3, 12);

        let original = PersistentState {
            paper_usd_balance: Decimal::new(1234567, 2), // 12345.67
            is_system_risk_frozen: true,
            session_pnl_cents: -4200,
            total_trades: 99,
            timestamp: 1_700_000_000,
            exchange_health,
        };

        // ---- save ----
        let worker = AsyncPersistenceWorker::new(&path_str, 1).0;
        let rt = tokio::runtime::Runtime::new().expect("failed to build runtime");
        rt.block_on(async {
            worker.save_state(&original).await.expect("save_state failed");
        });

        // ---- load ----
        let loaded = worker
            .load_state()
            .expect("load_state failed");

        assert_eq!(loaded.paper_usd_balance, original.paper_usd_balance);
        assert_eq!(loaded.is_system_risk_frozen, original.is_system_risk_frozen);
        assert_eq!(loaded.session_pnl_cents, original.session_pnl_cents);
        assert_eq!(loaded.total_trades, original.total_trades);
        assert_eq!(loaded.timestamp, original.timestamp);
        assert_eq!(loaded.exchange_health, original.exchange_health);
    }

    #[tokio::test]
    async fn test_channel_communication() {
        let dir = std::env::temp_dir().join("rust_hft_arb_test_chan");
        let _ = std::fs::create_dir_all(&dir);
        let file_path = dir.join("state_chan.json");
        let path_str = file_path.to_str().unwrap().to_string();

        let (worker, sender) = AsyncPersistenceWorker::new(&path_str, 4);

        // Spawn the disk-writer loop in the background.
        let handle = tokio::spawn(async move {
            worker.run_disk_writer_loop().await;
        });

        // Build a state and send it.
        let mut exchange_health = HashMap::new();
        exchange_health.insert(42, 3);

        let state = PersistentState {
            paper_usd_balance: Decimal::new(50000, 2),
            is_system_risk_frozen: false,
            session_pnl_cents: 100,
            total_trades: 7,
            timestamp: 1_710_000_000,
            exchange_health,
        };

        sender.send(state.clone()).await.expect("send failed");

        // Give the writer a moment to flush, then drop the sender so the loop exits.
        tokio::time::sleep(Duration::from_millis(200)).await;
        drop(sender);

        // Wait for the writer loop to finish.
        timeout(Duration::from_secs(2), handle)
            .await
            .expect("writer loop timed out")
            .expect("writer loop panicked");

        // Verify the file was written.
        let loaded = fs::read_to_string(file_path).expect("state file missing");
        let deserialized: PersistentState =
            serde_json::from_str(&loaded).expect("deserialization failed");

        assert_eq!(deserialized.paper_usd_balance, state.paper_usd_balance);
        assert_eq!(deserialized.is_system_risk_frozen, state.is_system_risk_frozen);
        assert_eq!(deserialized.session_pnl_cents, state.session_pnl_cents);
        assert_eq!(deserialized.total_trades, state.total_trades);
        assert_eq!(deserialized.timestamp, state.timestamp);
        assert_eq!(deserialized.exchange_health, state.exchange_health);
    }
}