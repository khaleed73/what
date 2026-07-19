//! CPU Core Pinning — Thread Affinity for HFT
//!
//! The spec requires: "CPU Core Pinning (Thread Affinity) — `core_affinity`
//! crate + `isolcpus` GRUB parameter"
//!
//! This module provides `spawn_pinned_trading_core` which pins the current
//! thread to a specific CPU core using the `core_affinity` crate. This
//! prevents OS scheduler migration and ensures cache warmth.
//!
//! The GRUB parameters (`isolcpus`, `nohz_full`, `rcu_nocbs`) are handled
//! by the deployment scripts (`setup_hft_server.sh`), not in Rust code.

use std::thread;

/// Number of retry attempts for CPU pinning after the initial attempt.
const PIN_RETRY_COUNT: u32 = 3;
/// Delay between pinning retry attempts in milliseconds.
const PIN_RETRY_DELAY_MS: u64 = 10;

/// Pin the current thread to a specific CPU core.
///
/// The spec defines: `core_affinity::set_for_current(core_id)`.
///
/// # Arguments
/// * `core_id` — The CPU core index to pin to (0-based).
///
/// # Returns
/// `true` if the pinning was successful, `false` otherwise.
#[inline]
pub fn pin_current_thread(core_id: usize) -> bool {
    let core_ids = core_affinity::get_core_ids().unwrap_or_default();
    if let Some(core) = core_ids.get(core_id) {
        if core_affinity::set_for_current(*core) {
            tracing::info!(core_id, "Thread pinned to CPU core");
            true
        } else {
            tracing::warn!(core_id, "Failed to pin thread to CPU core");
            false
        }
    } else {
        tracing::warn!(
            core_id,
            available_cores = core_ids.len(),
            "Requested core ID exceeds available cores"
        );
        false
    }
}

/// Spawn a new thread pinned to a specific CPU core and run the given closure.
///
/// This is the spec-mandated `spawn_pinned_trading_core` function.
///
/// # Arguments
/// * `core_id` — The CPU core index to pin to
/// * `name` — Thread name for identification
/// * `f` — The closure to execute on the pinned thread
///
/// # Returns
/// A `JoinHandle` for the spawned thread.
pub fn spawn_pinned_trading_core<F, T>(core_id: usize, name: &str, f: F) -> thread::JoinHandle<T>
where
    F: FnOnce() -> T + Send + Clone + 'static,
    T: Send + 'static,
{
    let name_owned = name.to_string();
    thread::Builder::new()
        .name(name_owned.clone())
        .spawn({
            let f = f.clone();
            move || {
                // Retry pinning up to `PIN_RETRY_COUNT` times with a short sleep between
                // attempts — the OS may temporarily fail affinity on first
                // try under load.
                let mut pinned = pin_current_thread(core_id);
                if !pinned {
                    for attempt in 1..=PIN_RETRY_COUNT {
                        std::thread::sleep(std::time::Duration::from_millis(PIN_RETRY_DELAY_MS));
                        pinned = pin_current_thread(core_id);
                        if pinned { break; }
                    }
                }
                if !pinned {
                    tracing::warn!(
                        thread = %name_owned,
                        core_id,
                        attempts = PIN_RETRY_COUNT + 1,
                        "Running on unpinned core after {} attempts — latency may be degraded",
                        PIN_RETRY_COUNT + 1
                    );
                }
                f()
            }
        })
        // NOTE: Thread spawn failure is logged at ERROR level and falls back
        // to an unpinned std::thread::spawn. For strict HFT deployments where
        // unpinned latency is unacceptable, replace the fallback with `panic!`.
        .unwrap_or_else(|e| {
            tracing::error!(error = %e, "Failed to spawn pinned trading thread, running unpinned");
            tracing::warn!("Failed to pin thread to core {}, running unpinned (latency degradation)", core_id);
            std::thread::spawn(f)
        })
}

/// Get the number of available CPU cores.
/// Returns 1 if core affinity detection fails.
#[inline]
pub fn available_cores() -> usize {
    core_affinity::get_core_ids()
        .map(|ids| ids.len())
        .unwrap_or(1)
}

/// Check if a specific core is available.
#[inline]
pub fn is_core_available(core_id: usize) -> bool {
    core_affinity::get_core_ids()
        .map(|ids| core_id < ids.len())
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_available_cores() {
        let cores = available_cores();
        assert!(cores >= 1);
    }

    #[test]
    fn test_pin_current_thread() {
        // Pin to core 0 — should succeed on any system with >= 1 core.
        let result = pin_current_thread(0);
        // May or may not succeed depending on the environment.
        // Don't assert — just verify no panic.
        let _ = result;
    }

    #[test]
    fn test_spawn_pinned_thread() {
        let handle = spawn_pinned_trading_core(0, "test-pinned", || {
            42
        });
        let result = handle.join().unwrap();
        assert_eq!(result, 42);
    }

    #[test]
    fn test_is_core_available() {
        // Core 0 should always be available.
        assert!(is_core_available(0));
    }

    #[test]
    fn test_out_of_range_core() {
        assert!(!is_core_available(99999));
    }
}